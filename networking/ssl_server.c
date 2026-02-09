/*
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
//config:config SSL_SERVER
//config:	bool "ssl_server (test TLS server)"
//config:	default y
//config:	select TLS
//config:	help
//config:	inetd-style TLS server. Stdin/stdout are already connected
//config:	to an accepted TCP socket.

//applet:IF_SSL_SERVER(APPLET(ssl_server, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_SSL_SERVER) += ssl_server.o

//usage:#define ssl_server_trivial_usage
//usage:       "[-vv] -p PRIVKEY.der -c CERT.der PROG ARGS"
//usage:#define ssl_server_full_usage ""

#include "libbb.h"

/* TLS server applet.
 *
 * To generate a test RSA certificate and key:
 * openssl req -x509 -newkey rsa:2048 -days 9999 -nodes \
 *     -subj '/CN=localhost' \
 *     -out cert.pem -keyout privkey.pem
 * Convert to DER format:
 * openssl x509 -in cert.pem -outform DER -out cert.der
 * openssl rsa -in privkey.pem -outform DER -out privkey.der
 *
 * Run the server:
 * tcpsvd 127.0.0.1 4433 ssl_server -p privkey.der -c cert.der -e echo 'Hello world'
 *
 * Test with:
 * openssl s_client -connect localhost:4433
 */
int ssl_server_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int ssl_server_main(int argc UNUSED_PARAM, char **argv)
{
	struct fd_pair to_prog;
	struct fd_pair from_prog;
	pid_t pid;
	tls_state_t *tls;
	const char *privkey_in_der_format;
	const char *cert_in_der_format;
	unsigned opt;

	tls = new_tls_state();

	/* "+": stop on first non-option */
	opt = getopt32(argv, "+""vp:c:",
		&privkey_in_der_format, &cert_in_der_format
	);
	argv += optind;
	if (!argv[0] || (opt >> 1) == 0)
		bb_show_usage();

	/* In inetd mode, stdin/stdout are the socket.
	 * But tls_run_copy_loop() needs *non-TLS* fds on STDIN and STDOUT.
	 * Shuffle them.
	 */
	xdup2(STDIN_FILENO, 3);
	xdup2(STDOUT_FILENO, 4);
	tls->ifd = 3;
	tls->ofd = 4;

	/* This can abort on errors */
	tls_handshake_as_server(tls, privkey_in_der_format, cert_in_der_format);

	/* Run PROG, wrap its data in TLS and I/O to socket */
	xpiped_pair(to_prog);
	xpiped_pair(from_prog);
	pid = xvfork();
	if (pid == 0) {
		/* Child: run the program */

		/* NB: close _first_, then move fds! */
		close(to_prog.wr);
		close(from_prog.rd);
		xmove_fd(to_prog.rd, STDIN_FILENO);
		xmove_fd(from_prog.wr, STDOUT_FILENO);

		BB_EXECVP_or_die(argv);
	}
	/* Parent: close child ends of pipes */
	close(to_prog.rd);
	close(from_prog.wr);

	/* tls_run_copy_loop() needs non-TLS fds on STDIN and STDOUT */
	xmove_fd(from_prog.rd, STDIN_FILENO);
	xmove_fd(to_prog.wr, STDOUT_FILENO);
	tls_run_copy_loop(tls, /*flags*/ 0
//flags????
);
	return EXIT_SUCCESS;
}
