/* cg-itk 1.0: cgroups-capable multiuser security module for Apache 2.4 */
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Portions copyright 2017-2018 Aleksey Gerasimov <enclaved@vanillablood.art>.
 * Licensed under the same terms as the rest of Apache.
 *
 * Portions copyright 2005-2016 Steinar H. Gunderson <sgunderson@bigfoot.com>.
 * Licensed under the same terms as the rest of Apache.
 *
 * Portions copyright 2008 Knut Auvor Grythe <knut@auvor.no>.
 * Licensed under the same terms as the rest of Apache.
 */
#include "cg_itk.h"

/* {{{ Apache headers */
#include <httpd.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include <http_protocol.h>
#include <http_request.h>
#include <ap_listen.h>
#include <mpm_common.h>
#include <scoreboard.h>
#ifndef	HAVE_LIBCAP
#include <unixd.h>
#endif	/* HAVE_LIBCAP */
/* }}} */

/* {{{ APR headers */
#include <apr.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_ring.h>
#include <apr_signal.h>
#include <apr_strings.h>
#ifdef	linux
#include <apr_tables.h>
#endif	/* linux */
#include <apr_user.h>
#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include <apr_want.h>
/* }}} */

/* {{{ System headers */
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#ifdef	HAVE_LIBCAP
#include <sys/capability.h>
#include <sys/prctl.h>
#endif	/* HAVE_LIBCAP */
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
/* }}} */

/* Children SIGTERM timeout */
#define	GRACEFUL_DEATH	3

/* Per-vhost configuration */
typedef struct {
	unsigned long		vmax;		/* max clients/server */
	unsigned long		rrto;		/* ReqRunTimeout bomb */
	apr_uid_t			suid;		/* UID to setuid() to */
	apr_gid_t			sgid;		/* GID to setgid() to */
#ifdef	linux
	apr_array_header_t	*cgvec;		/* cgroups membership */
#define	CGVEC_PREALLOC	3			/* initial cgvec size */
#endif	/* linux */
} itk_server_conf;

/* Forward declaration for ITK_SERVER_CONF() */
module AP_MODULE_DECLARE_DATA cg_itk_module;
/*
 * Convenience macro for extracting an itk_server_conf pointer
 * from structures that harbor a server_rec component pointer.
 */
#define	ITK_SERVER_CONF(x)								\
	((itk_server_conf *)ap_get_module_config(			\
		(x)->server->module_config, &cg_itk_module))

#ifdef	HAVE_LIBCAP
static cap_t itk_caps;
#define	sizeof_array(x)		(sizeof((x)) / sizeof(*(x)))
#else	/* HAVE_LIBCAP */
static apr_uid_t itk_unixd_uid;		/* saved unixd UID */
static apr_gid_t itk_unixd_gid;		/* saved unixd GID */
#endif	/* HAVE_LIBCAP */

/* Irreversible setuid() flag */
static int itk_setuid;
/* Current request being processed */
static request_rec *itk_request = NULL;

/*----------------------------------------------------------------------------
 *	Routines
 *--------------------------------------------------------------------------*/

/* {{{ itk_exit() */
static INLINE NORETURN void
itk_exit(conn_rec *c, int exitcode)
{
	ap_lingering_close(c);
	_Exit(exitcode);
}
/* }}} */

/* {{{ itk_forceful_death() */
static NORETURN void
itk_forceful_death(int sig)
{
	apr_killpg(GETPGRP(), SIGKILL);
	_Exit(APEXIT_OK);
}
/* }}} */

/* {{{ itk_graceful_death() */
static NORETURN COLD void
itk_graceful_death(int sig)
{
	/* If inside a request, special handling is required */
	if (itk_request != NULL) {
		itk_server_conf *cf = ITK_SERVER_CONF(itk_request);
		apr_status_t status;

		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, itk_request,
			APLOGNO(80800) "ReqRunTimeout %li exceeded", cf->rrto);

		/* Close the current request's connection */
		ap_lingering_close(itk_request->connection);

		/* Arrange for SIGKILL via SIGALRM */
		apr_signal(SIGALRM, itk_forceful_death);
		alarm(GRACEFUL_DEATH);

		/* Ignore all common signals */
		apr_signal(SIGTERM, SIG_IGN);
		apr_signal(SIGINT, SIG_IGN);
		apr_signal(SIGHUP, SIG_IGN);
		apr_signal(AP_SIG_GRACEFUL, SIG_IGN);
		apr_signal(AP_SIG_GRACEFUL_STOP, SIG_IGN);

		/* Kill the entire process group */
		apr_killpg(GETPGRP(), SIGTERM);
		do {
			apr_proc_t proc;
			int exitcode;
			apr_exit_why_e why;

			/* Wait for the next random child to terminate */
			status = apr_proc_wait_all_procs(&proc, &exitcode, &why,
				APR_WAIT, ap_server_conf->process->pool);

			/* Write an epitapth on the cause of death, if any */
			if (APR_STATUS_IS_CHILD_DONE(status)) {
				if (APR_PROC_CHECK_EXIT(why) && exitcode != APEXIT_OK)
					ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, itk_request,
						APLOGNO(80810) "child %d exited with code %d",
						proc.pid, exitcode);
				if (APR_PROC_CHECK_SIGNALED(why))
					ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, itk_request,
						APLOGNO(80811) "child %d terminated by signal %d",
						proc.pid, exitcode);
				if (APR_PROC_CHECK_CORE_DUMP(why))
					ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, itk_request,
						APLOGNO(80012) "child %d produced a core dump",
						proc.pid);
			}
		} while (status != ECHILD);
	}
	_Exit(APEXIT_OK);
}
/* }}} */

/*----------------------------------------------------------------------------
 *	Hooks
 *--------------------------------------------------------------------------*/

/* {{{ itk_hook_drop_privileges_first() */
static HOT NONNULL int
itk_hook_drop_privileges_first(apr_pool_t *p, server_rec *s)
{
#ifdef	HAVE_LIBCAP
	if (prctl(PR_SET_KEEPCAPS, 1) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
			APLOGNO(80900) "prctl(PR_SET_KEEPCAPS, 1)");
		_Exit(APEXIT_CHILDINIT);
	}
#else	/* HAVE_LIBCAP */
	itk_unixd_uid = ap_unixd_config.user_id;
	itk_unixd_gid = ap_unixd_config.group_id;
	ap_unixd_config.user_id = 0;
	ap_unixd_config.group_id = 0;
#endif	/* HAVE_LIBCAP */

	return OK;
}
/* }}} */

/* {{{ itk_hook_drop_privileges_last() */
static HOT NONNULL int
itk_hook_drop_privileges_last(apr_pool_t *p, server_rec *s)
{
#ifdef	HAVE_LIBCAP
	static const cap_value_t capv[] = {
		CAP_IPC_OWNER,
		CAP_SETUID,
		CAP_SETGID,
		CAP_DAC_OVERRIDE,
	};

	if (prctl(PR_SET_KEEPCAPS, 0) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
			APLOGNO(80910) "prctl(PR_SET_KEEPCAPS, 0)");
		_Exit(APEXIT_CHILDINIT);
	}
	itk_caps = cap_init();

	/* Drop most of current capabilities */
	if (itk_caps == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
			APLOGNO(80920) "cap_init()");
		_Exit(APEXIT_CHILDINIT);
	}
	if (cap_clear(itk_caps) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
			APLOGNO(80921) "cap_clear()");
		_Exit(APEXIT_CHILDINIT);
	}
	if (cap_set_flag(itk_caps, CAP_PERMITTED, sizeof_array(capv),
		capv, CAP_SET) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
			APLOGNO(80922) "cap_set_flag(CAP_PERMITTED)");
		_Exit(APEXIT_CHILDINIT);
	}
	if (cap_set_flag(itk_caps, CAP_EFFECTIVE, sizeof_array(capv),
		capv, CAP_SET) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
			APLOGNO(80923) "cap_set_flag(CAP_EFFECTIVE)");
		_Exit(APEXIT_CHILDINIT);
	}
	if (cap_set_proc(itk_caps) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
			APLOGNO(80924) "cap_set_proc()");
		_Exit(APEXIT_CHILDINIT);
	}

#else	/* HAVE_LIBCAP */
	ap_unixd_config.user_id = itk_unixd_uid;
	ap_unixd_config.group_id = itk_unixd_gid;
#endif	/* HAVE_LIBCAP */

	return OK;
}
/* }}} */

/* {{{ itk_hook_process_connection() */
static HOT NONNULL int
itk_hook_process_connection(conn_rec *c)
{
	static apr_status_t status = APR_INPARENT;
	apr_proc_t proc;

	/* Resolve in-child fork() loops */
	if (APR_STATUS_IS_INCHILD(status))
		return DECLINED;

	status = apr_proc_fork(&proc, c->pool);
	if (APR_STATUS_IS_INCHILD(status)) {
		ap_close_listeners();

		/* Make a process group (signal domain) */
		if (SETPGRP() == -1) {
#ifdef	SETPGRP_VOID
			ap_log_cerror(APLOG_MARK, APLOG_ERR, errno, c,
				APLOGNO(80002) "setpgrp()");
#else	/* SETPGRP_VOID */
			ap_log_cerror(APLOG_MARK, APLOG_ERR, errno, c,
				APLOGNO(80002) "setpgrp(0, 0)");
#endif	/* SETPGRP_VOID */
			itk_exit(c, APEXIT_CHILDINIT);
		}
		apr_signal(SIGTERM, itk_graceful_death);
		apr_signal(SIGINT, itk_graceful_death);
		apr_signal(SIGHUP, itk_graceful_death);
		apr_signal(SIGALRM, itk_graceful_death);
		apr_signal(AP_SIG_GRACEFUL, itk_graceful_death);
		apr_signal(AP_SIG_GRACEFUL_STOP, itk_graceful_death);

		ap_run_process_connection(c);
		itk_exit(c, APEXIT_OK);
	}
	if (APR_STATUS_IS_INPARENT(status)) {
		ap_generation_t gen = ap_scoreboard_image->global->running_generation;
		int exitcode;
		apr_exit_why_e why;

		ap_register_extra_mpm_process(proc.pid, gen);

		/* Wait for the child to terminate (loop to handle EINTR) */
		do status = apr_proc_wait(&proc, &exitcode, &why, APR_WAIT);
		while (APR_STATUS_IS_CHILD_NOTDONE(status));

		ap_unregister_extra_mpm_process(proc.pid, &gen);

		if (APR_PROC_CHECK_EXIT(why) && exitcode != APEXIT_OK)
			ap_log_cerror(APLOG_MARK, APLOG_NOTICE, 0, c, APLOGNO(80010)
				"child %d exited with code %d", proc.pid, exitcode);
		if (APR_PROC_CHECK_SIGNALED(why))
			ap_log_cerror(APLOG_MARK, APLOG_NOTICE, 0, c, APLOGNO(80011)
				"child %d terminated by signal %d", proc.pid, exitcode);
		if (APR_PROC_CHECK_CORE_DUMP(why))
			ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c, APLOGNO(80012)
				"child %d produced a core dump", proc.pid);

		apr_socket_close(ap_get_conn_socket(c));
		ap_set_core_module_config(c->conn_config, NULL);
	} else
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
			APLOGNO(80001) "apr_proc_fork()");

	return OK;
}
/* }}} */

/* {{{ itk_hook_post_config() */
static COLD NONNULL int
itk_hook_post_config(
	apr_pool_t		*pconf,
	apr_pool_t		*plog,
	apr_pool_t		*ptemp,
	server_rec		*s)
{
	int threaded;

	ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded);
	if (threaded) {
		ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, ptemp,
			APLOGNO(80000) PACKAGE " does not support threaded MPMs");
		return OK ^ DECLINED;
	}

	ap_add_version_component(pconf, PACKAGE "/" VERSION);
	return OK;
}
/* }}} */

/* {{{ itk_hook_post_perdir_config() */
static HOT NONNULL int
itk_hook_post_perdir_config(request_rec *r)
{
	itk_server_conf *cf = ITK_SERVER_CONF(r);

	/* Enforce MaxClientsVHost */
	if (cf->vmax != 0) {
		const char *vhost = apr_psprintf(r->pool, "%s:%d",
			r->server->server_hostname, r->connection->local_addr->port);
		int i, n = 0;

		ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &i);
		/*
		 * Note: this method of counting connections per vhost is wrong.
		 * The vhost member of worker_score is too short to accomodate
		 * accurate information; matching it can yield false positives.
		 */
		while (i > 0) {
			worker_score *ws = ap_get_scoreboard_worker_from_indexes(--i, 0);
			n += ws->status >= SERVER_BUSY_READ && !strcmp(ws->vhost, vhost);
		}
		if (n > cf->vmax) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(80100)
				"%s: MaxClientsVHost reached", r->server->server_hostname);
			return HTTP_SERVICE_UNAVAILABLE;
		}
	}

	/* Arm the ReqRunTimeout bomb */
	if (cf->rrto != 0) {
		itk_request = r;
		alarm(cf->rrto);
	}
	if (!itk_setuid) {
		apr_status_t status;
		apr_uid_t uid;
		apr_gid_t gid;
#ifdef	linux
		int i = cf->cgvec->nelts;

		/* Write our PID to all cgroups' task files */
		while (i > 0) {
			char *cg = APR_ARRAY_IDX(cf->cgvec, --i, char *);
			int fd = open(cg, O_WRONLY|O_SYNC);

			if (fd == -1) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
					APLOGNO(80110) "open(\"%s\")", cg);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (dprintf(fd, "%d\n", getpid()) < 0) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
					APLOGNO(80111) "dprintf(%d)", fd);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (close(fd) == -1) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
					APLOGNO(80112) "close(%d)", fd);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
#endif	/* linux */

		/* Get current process credentials */
		status = apr_uid_current(&uid, &gid, r->pool);
		if (status != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
				APLOGNO(80121) "apr_uid_current()");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (cf->sgid != 0) {
			char *user;

			/* Get username of the desired UID */
			status = apr_uid_name_get(&user, cf->suid, r->pool);
			if (status != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					APLOGNO(80120) "apr_uid_name_get(%d)", cf->suid);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			/* Compare and set GID, if necessary */
			status = apr_gid_compare(gid, cf->sgid);
			if (APR_STATUS_IS_BADARG(status)) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
					APLOGNO(80122) "apr_gid_compare(%d, %d)", gid, cf->sgid);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (APR_STATUS_IS_EMISMATCH(status) && setgid(cf->sgid) == -1) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
					APLOGNO(80123) "setgid(%d)", cf->sgid);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			/* Initialize supplementary groups */
			if (initgroups(user, cf->sgid) == -1) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
					APLOGNO(80124) "initgroups(\"%s\", %d)", user, cf->sgid);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		if (cf->suid != 0) {
			/* Compare and set UID, if necessary */
			status = apr_uid_compare(uid, cf->suid);
			if (APR_STATUS_IS_BADARG(status)) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
					APLOGNO(80125) "apr_uid_compare(%d, %d)", uid, cf->suid);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (APR_STATUS_IS_EMISMATCH(status) && setuid(cf->suid) == -1) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
					APLOGNO(80126) "setuid(%d)", cf->suid);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}

#ifdef	HAVE_LIBCAP
		/* Drop all remaining capabilities */
		if (cap_clear(itk_caps) == -1) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
				APLOGNO(80130) "cap_clear()");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		if (cap_set_proc(itk_caps) == -1) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
				APLOGNO(80131) "cap_set_proc()");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		if (cap_free(itk_caps) == -1) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
				APLOGNO(80132) "cap_free()");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
#endif	/* HAVE_LIBCAP */

		/* Mark this as a point of no return */
		itk_setuid = 1;
	}

#ifdef	HAVE_SETPROCTITLE
	setproctitle("%s %s %s %s", r->useragent_ip,
		r->hostname, r->method, r->unparsed_uri);
#endif	/* HAVE_SETPROCTITLE */

	return OK;
}
/* }}} */

/* {{{ itk_hook_log_transaction() */
static HOT NONNULL int
itk_hook_log_transaction(request_rec *r)
{
	/* Disarm the ReqRunTimeout bomb */
	itk_request = NULL;
	alarm(0);

#ifdef	HAVE_SETPROCTITLE
	if (r->connection->keepalive == AP_CONN_KEEPALIVE)
		setproctitle("keepalive from %s", r->useragent_ip);
#endif	/* HAVE_SETPROCTITLE */

	return OK;
}
/* }}} */

/* {{{ itk_hook_dirwalk_stat() */
static HOT NONNULL apr_status_t
itk_hook_dirwalk_stat(
	apr_finfo_t		*finfo,
	request_rec		*r,
	apr_int32_t		wanted)
{
	apr_status_t status = apr_stat(finfo, r->filename, wanted, r->pool);

	if (itk_setuid && r->main == NULL && APR_STATUS_IS_EACCES(status)) {
		ap_log_rerror(APLOG_MARK, APLOG_NOTICE, status, r,
			APLOGNO(80501) "apr_stat(\"%s\")", r->filename);
		itk_exit(r->connection, APEXIT_OK);
	}
	return status;
}
/* }}} */

/* {{{ itk_hook_open_htaccess() */
static HOT NONNULL apr_status_t
itk_hook_open_htaccess(
	request_rec		*r,
	const char		*dir_name,
	const char		*access_name,
	ap_configfile_t	**conffile,
	const char		**full_name)
{
	apr_status_t status = AP_DECLINED;

	if (itk_setuid && r->main == NULL) {
		*full_name = ap_make_full_path(r->pool, dir_name, access_name);
		status = ap_pcfg_openfile(conffile, r->pool, *full_name);

		if (APR_STATUS_IS_EACCES(status)) {
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE, status, r,
				APLOGNO(80502) "ap_pcf_openfile(\"%s\")", *full_name);
			itk_exit(r->connection, APEXIT_OK);
		}
	}
	return status;
}
/* }}} */

/*----------------------------------------------------------------------------
 *	Configuration
 *--------------------------------------------------------------------------*/

/* {{{ itk_sconf_vmax() */
static COLD const char *
itk_sconf_vmax(cmd_parms *cmd, void *x, const char *arg)
{
	itk_server_conf *cf = ITK_SERVER_CONF(cmd);
	const char *end;

	errno = 0;
	cf->vmax = strtoul(arg, (char **)&end, 0);

	if (errno != 0)
		return strerror(errno);
	if (end == arg || *end != 0)
		return strerror(EINVAL);
	if (cf->vmax < 0)
		return strerror(ERANGE);

	return NULL;
}
/* }}} */

/* {{{ itk_sconf_rrto() */
static COLD const char *
itk_sconf_rrto(cmd_parms *cmd, void *x, const char *arg)
{
	itk_server_conf *cf = ITK_SERVER_CONF(cmd);
	const char *end;

	errno = 0;
	cf->rrto = strtoul(arg, (char **)&end, 0);

	if (errno != 0)
		return strerror(errno);
	if (end == arg || *end != 0)
		return strerror(EINVAL);
	if (cf->rrto < 0)
		return strerror(ERANGE);

	return NULL;
}
/* }}} */

/* {{{ itk_sconf_dac() */
static COLD const char *
itk_sconf_dac(cmd_parms *cmd, void *x, const char *uname, const char *gname)
{
	itk_server_conf *cf = ITK_SERVER_CONF(cmd);

	cf->suid = ap_uname2id(uname);
	cf->sgid = ap_gname2id(gname);

	return NULL;
}
/* }}} */

#ifdef	linux
/* {{{ itk_sconf_cgroup() */
static COLD const char *
itk_sconf_cgroup(cmd_parms *cmd, void *x, const char *arg)
{
	itk_server_conf *cf = ITK_SERVER_CONF(cmd);

	APR_ARRAY_PUSH(cf->cgvec, char *) = apr_pstrdup(cmd->pool, arg);
	return NULL;
}
/* }}} */
#endif	/* linux */

/*----------------------------------------------------------------------------
 *	Module
 *--------------------------------------------------------------------------*/

/* {{{ itk_sconf_cmdv[] */

static const command_rec itk_sconf_cmdv[] = {
	AP_INIT_TAKE2("AssignUserID", itk_sconf_dac, NULL, RSRC_CONF,
		"Tie a virtual host to a specific child process."),
	AP_INIT_TAKE1("MaxClientsVHost", itk_sconf_vmax, NULL, RSRC_CONF,
		"Maximum number of worker children per virtual host."),
#ifdef	linux
	AP_INIT_ITERATE("CGroups", itk_sconf_cgroup, NULL, RSRC_CONF,
		"Add this VHost's children to the specified cgroup(s)."),
#endif	/* linux */
	AP_INIT_TAKE1("ReqRunTimeout", itk_sconf_rrto, NULL, RSRC_CONF,
		"Maximum time in seconds allowed to a single request."),
	{NULL}
};

/* }}} */

/* {{{ itk_sconf_init() */
static COLD void *
itk_sconf_init(apr_pool_t *p, server_rec *s)
{
	itk_server_conf *cf = (itk_server_conf *)apr_palloc(p, sizeof(*cf));

	cf->vmax = 0;	/* inapplicable */
	cf->rrto = 0;	/* inapplicable */
	cf->suid = 0;	/* inapplicable */
	cf->sgid = 0;	/* inapplicable */
#ifdef	linux
	cf->cgvec = apr_array_make(p, CGVEC_PREALLOC, sizeof(char *));
#endif	/* linux */

	return cf;
}
/* }}} */

/* {{{ itk_sconf_merge() */
static COLD void *
itk_sconf_merge(apr_pool_t *p, void *_cb, void *_co)
{
	itk_server_conf *cb = (itk_server_conf *)_cb;	/* baseconf */
	itk_server_conf *co = (itk_server_conf *)_co;	/* override */
	itk_server_conf *cf = (itk_server_conf *)apr_palloc(p, sizeof(*cf));

	cf->vmax = co->vmax != 0 ? co->vmax : cb->vmax;
	cf->rrto = co->rrto != 0 ? co->rrto : cb->rrto;
	cf->suid = co->suid != 0 ? co->suid : cb->suid;
	cf->sgid = co->sgid != 0 ? co->sgid : cb->sgid;
#ifdef	linux
	cf->cgvec = apr_array_append(p, cb->cgvec, co->cgvec);
#endif	/* linux */

	return cf;
}
/* }}} */

/* {{{ itk_register_hooks() */
static COLD void
itk_register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(itk_hook_post_config,
		NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_drop_privileges(itk_hook_drop_privileges_first,
		NULL, NULL, APR_HOOK_FIRST);
	ap_hook_drop_privileges(itk_hook_drop_privileges_last,
		NULL, NULL, APR_HOOK_LAST);
	ap_hook_process_connection(itk_hook_process_connection,
		NULL, NULL, APR_HOOK_REALLY_FIRST);
	ap_hook_post_perdir_config(itk_hook_post_perdir_config,
		NULL, NULL, APR_HOOK_REALLY_FIRST);
	ap_hook_log_transaction(itk_hook_log_transaction,
		NULL, NULL, APR_HOOK_REALLY_LAST);
	/*
	 * It is possible that we're in a persistent connection where
	 * subsequent requests may come for vhosts we no longer have
	 * access to due to setuid() and setgid().  Therefore we need
	 * to wrap around dirwalk and .htaccess operations with these
	 * hooks in order to fail gracefully should that be the case.
	 */
	ap_hook_dirwalk_stat(itk_hook_dirwalk_stat,
		NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_open_htaccess(itk_hook_open_htaccess,
		NULL, NULL, APR_HOOK_REALLY_FIRST);
}
/* }}} */

/* {{{ AP_DECLARE_MODULE(cg_itk) */

AP_DECLARE_MODULE(cg_itk) = {
	STANDARD20_MODULE_STUFF,
	NULL,				/* create per-directory config */
	NULL,				/* merge per-directory configs */
	itk_sconf_init,		/* create per-server config */
	itk_sconf_merge,	/* merge per-server configs */
	itk_sconf_cmdv,		/* config directives vector */
	itk_register_hooks,	/* place for hook registering */
};

/* }}} */

/*
 * vim: ts=4 sw=4 fdm=marker
 */
