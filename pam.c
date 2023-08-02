#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <u.h>
#include <args.h>
#include <libc.h>
#include <auth.h>
#include <authsrv.h>
#include <libsec.h>

#include "fncs.h"

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv )
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

char *authserver;

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv )
{
	char *username;
	char *password;
	int fd;
	AuthInfo *ai;

	if(pam_get_user(pamh, &username, NULL) != PAM_SUCCESS)
		return PAM_AUTH_ERR;
	if(pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL) != PAM_SUCCESS)
		return PAM_AUTH_ERR;

	if(argc != 1)
		return PAM_AUTH_ERR;

	authserver = argv[0];

	fd = unix_dial(authserver, "17019");
	if(fd < 0)
		return PAM_AUTH_ERR;

	ai = p9any(username, password, fd);
	close(fd);

	if(ai == nil)
		return PAM_AUTH_ERR;

	return PAM_SUCCESS;
}
