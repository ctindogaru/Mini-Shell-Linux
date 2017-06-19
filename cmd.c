// Dogaru Constantin 333CC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "cmd.h"
#include "utils.h"

#define READ			0
#define WRITE			1
#define MAX_ARGS		8
#define MAX_NAME_SIZE	200
#define FLAG_STDIN		3

static char *var;
static char *value;
static char **args;

static void alloc_mem(void)
{
	args = (char **) malloc(MAX_ARGS * sizeof(char *));
}

static char *expand(const char *key)
{
	/* TODO - Return the value of environment variable */
	if (getenv(key))
		return getenv(key);
	else
		return "";
}

static void set_var(const char *var, const char *value)
{
	/* TODO - Set the environment variable */
	setenv(var, value, 1);
}

static char *get_full_name(word_t *s)
{
	char *full_name = (char *) malloc(sizeof(char) * MAX_NAME_SIZE);
	word_t *head = s;

	strcpy(full_name, "");

	while (s != NULL) {
		if (s->expand)
			strcat(full_name, expand(s->string));
		else
			strcat(full_name, s->string);
		s = s->next_part;
	}
	s = head;

	return full_name;
}

static void set_parameters(simple_command_t *s)
{
	int k = 0;
	word_t *head = s->params;

	if (s->verb != NULL)
		args[0] = strdup(s->verb->string);

	k = 1;
	while (s->params != NULL) {
		char *full_name = get_full_name(s->params);

		args[k] = strdup(full_name);
		free(full_name);
		s->params = s->params->next_word;
		k++;
	}
	s->params = head;

	args[k] = NULL;
}

static void do_redirect(int filedes, word_t *std, int flags,
	const char *command_name)
{
	int ret;
	int fd;
	char *filename = get_full_name(std);

	/* TODO - Redirect filedes into file filename */
	if (flags == 0)
		fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	else if (flags == 1 || flags == 2)
		fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
	else
		fd = open(filename, O_RDONLY);
	free(filename);

	DIE(fd < 0, "open");

	if (strcmp(command_name, "cd") != 0) {
		ret = dup2(fd, filedes);
		DIE(ret < 0, "dup2");
	}

	close(fd);
}

static void redirect_all(simple_command_t *s)
{
	const char *command_name = s->verb->string;

	if (s->in != NULL)
		do_redirect(STDIN_FILENO, s->in, FLAG_STDIN, command_name);
	if (s->out != NULL)
		do_redirect(STDOUT_FILENO, s->out, s->io_flags, command_name);
	if (s->err != NULL)
		do_redirect(STDERR_FILENO, s->err, s->io_flags, command_name);
	if (s->out != NULL && s->err != NULL
		&& strcmp(s->out->string, s->err->string) == 0
		&& strcmp(command_name, "cd") != 0)
		dup2(STDOUT_FILENO, STDERR_FILENO);
}

/**
 * Internal exit/quit command.
 */
static void shell_exit(void)
{
	/* TODO execute exit/quit */
	exit(EXIT_SUCCESS);
	/* TODO replace with actual exit code */
}

/**
 * Internal change-directory command.
 */
static int shell_cd(word_t *dir)
{
	/* TODO execute cd */

	int exit_status = 0;
	char cwd[MAX_NAME_SIZE];
	char *path = get_full_name(dir);

	if (path[0] == '/') {
		exit_status = chdir(path);
		if (exit_status == -1) {
			free(path);
			return EXIT_FAILURE;
		}
	} else {
		getcwd(cwd, sizeof(cwd));
		strcat(cwd, "/");
		strcat(cwd, path);
		exit_status = chdir(cwd);
		if (exit_status == -1) {
			free(path);
			return EXIT_FAILURE;
		}
	}

	free(path);
	return EXIT_SUCCESS;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO sanity checks */

	const char *command_name = s->verb->string;
	word_t *assign = NULL;
	word_t *value_assign = NULL;
	pid_t pid, wait_ret;
	int status;

	/* TODO if builtin command, execute the command */

	if (strcmp(command_name, "exit") == 0 ||
		strcmp(command_name, "quit") == 0) {
		shell_exit();
	}

	if (strcmp(command_name, "cd") == 0) {
		redirect_all(s);
		return shell_cd(s->params);
	}

	assign = s->verb->next_part;

	if (assign != NULL) {
		value_assign = assign->next_part;

		if (value_assign != NULL) {
			var = strdup(command_name);
			value = strdup(value_assign->string);
			set_var(var, value);
			return EXIT_SUCCESS;
		}
		return EXIT_FAILURE;
	}

	alloc_mem();
	set_parameters(s);

	/* TODO - Create a process to execute the command */
	pid = fork();
	switch (pid) {
	case -1:	/* error */
		perror("fork");
		return EXIT_FAILURE;

	case 0:		/* child process */
		redirect_all(s);

		execvp(s->verb->string, (char *const *) args);

		fprintf(stderr, "Execution failed for '%s'\n", s->verb->string);
		fflush(stdout);

		exit(EXIT_FAILURE);

	default:	/* parent process */
		wait_ret = waitpid(pid, &status, 0);
		DIE(wait_ret < 0, "wait_ret");
	}

	if (strcmp(command_name, "false") == 0)
		return EXIT_FAILURE;

	return WEXITSTATUS(status); /* TODO replace with actual exit status */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
	command_t *father)
{
	/* TODO execute cmd1 and cmd2 simultaneously */

	pid_t pid, wait_ret;
	int status;

	pid = fork();
	switch (pid) {
	case -1:
		perror("fork");
		return EXIT_FAILURE;

	case 0:
		parse_command(cmd1, level, father);
		exit(EXIT_FAILURE);

	default:
		parse_command(cmd2, level, father);
		wait_ret = waitpid(pid, &status, 0);
		DIE(wait_ret < 0, "wait_ret");
	}

	return WEXITSTATUS(status);
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
	command_t *father)
{
	int p[2];
	int status1;
	pid_t pid1, pid2;

	if (pipe(p) < 0)
		return -1;

	pid1 = fork();
	switch (pid1) {
	case -1:
		printf("unable to fork!\n");
		return -1;

	case 0:
		/* child process */
		pid2 = fork();
		switch (pid2) {
		case -1:
			printf("unable to fork!\n");
			return -1;

		case 0:
			/* child process */
			close(STDOUT_FILENO);
			dup(p[1]);
			close(p[0]);

			parse_command(cmd1, level, father);
			exit(EXIT_FAILURE);

		default:
			/* parent process */
			close(STDIN_FILENO);
			dup(p[0]);
			close(p[1]);

			parse_command(cmd2, level, father);
		}
		break;

	default:
		/* parent process */
		close(p[0]);
		close(p[1]);
		waitpid(pid1, &status1, 0);

		return status1;
	}

	return EXIT_SUCCESS;
}

static void execute_commands_seq(command_t *c, int level,
	command_t *father)
{
	parse_command(c->cmd1, level + 1, c);
	parse_command(c->cmd2, level + 1, c);
}

static bool execute_commands_non_zero(command_t *c, int level,
	command_t *father)
{
	bool result = parse_command(c->cmd1, level + 1, c);

	if (result == EXIT_SUCCESS)
		return EXIT_SUCCESS;
	else
		return parse_command(c->cmd2, level + 1, c);
}

static bool execute_commands_zero(command_t *c, int level,
	command_t *father)
{
	bool result = parse_command(c->cmd1, level + 1, c);

	if (result == EXIT_FAILURE)
		return EXIT_FAILURE;
	else
		return parse_command(c->cmd2, level + 1, c);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO sanity checks */

	if (c->op == OP_NONE) {
		/* TODO execute a simple command */
		return parse_simple(c->scmd, level, father);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO execute the commands one after the other */

		execute_commands_seq(c, level, father);

		break;

	case OP_PARALLEL:
		/* TODO execute the commands simultaneously */

		return do_in_parallel(c->cmd1, c->cmd2, level, father);

		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO execute the second command only if the first one
		 * returns non zero
		 */

		return execute_commands_non_zero(c, level, father);

		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO execute the second command only if the first one
		 * returns zero
		 */

		return execute_commands_zero(c, level, father);

		break;

	case OP_PIPE:
		/* TODO redirect the output of the first command to the
		 * input of the second
		 */

		return do_on_pipe(c->cmd1, c->cmd2, level, father);

		break;

	default:
		return SHELL_EXIT;
	}

	return EXIT_SUCCESS; /* TODO replace with actual exit code of command */
}
