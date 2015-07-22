/*-------------------------------------------------------------------------
 *
 * jsonlog.c
 *		Facility using hook controlling logging output of a Postgres
 *		able to generate JSON logs
 *
 * Copyright (c) 2013-2015, Michael Paquier
 * Copyright (c) 1996-2015, PostgreSQL Global Development Group
 * Copyright (c) 2015, MasBog infra Development
 *
 * IDENTIFICATION
 *		jsonlog.c/jsonlog.c
 *
 *-------------------------------------------------------------------------
 */

#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include "postgres.h"
#include "libpq/libpq.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "access/xact.h"
#include "access/transam.h"
#include "lib/stringinfo.h"
#include "postmaster/syslogger.h"
#include "storage/proc.h"
#include "utils/elog.h"
#include "utils/guc.h"
#include "utils/json.h"

/* Allow load of this module in shared libs */
PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

/* Hold previous logging hook */
static emit_log_hook_type prev_log_hook = NULL;

/* Log timestamp */
#define LOG_TIMESTAMP_LEN 128
static char log_time[LOG_TIMESTAMP_LEN];
static double time_stamp_epoch;
static const char *error_severity(int elevel);
static void write_jsonlog(ErrorData *edata);

/*
 * error_severity
 * Print string showing error severity based on integer level.
 * Taken from elog.c.
 */
static const char *
error_severity(int elevel)
{
	const char *prefix;

	switch (elevel)
	{
		case DEBUG1:
		case DEBUG2:
		case DEBUG3:
		case DEBUG4:
		case DEBUG5:
			prefix = _("DEBUG");
			break;
		case LOG:
		case COMMERROR:
			prefix = _("LOG");
			break;
		case INFO:
			prefix = _("INFO");
			break;
		case NOTICE:
			prefix = _("NOTICE");
			break;
		case WARNING:
			prefix = _("WARNING");
			break;
		case ERROR:
			prefix = _("ERROR");
			break;
		case FATAL:
			prefix = _("FATAL");
			break;
		case PANIC:
			prefix = _("PANIC");
			break;
		default:
			prefix = "???";
			break;
	}

	return prefix;
}

static char *substring(char *string, int position, int length)
{
   char *pointer;
   int c;

   pointer = malloc(length+1);

   if( pointer == NULL )
       exit(EXIT_FAILURE);

   for( c = 0 ; c < length ; c++ )
      *(pointer+c) = *((string+position-1)+c);

   *(pointer+c) = '\0';

   return pointer;
}

static void insert_substring(char *a, char *b, int position)
{
   char *f, *e;
   int length;

   length = strlen(a);

   f = substring(a, 1, position - 1 );
   e = substring(a, position, length-position+1);

   strcpy(a, "");
   strcat(a, f);
   free(f);
   strcat(a, b);
   strcat(a, e);
   free(e);
}

static void
write_pipe_chunks(char *data, int len)
{
	PipeProtoChunk p;
	int		 fd = fileno(stderr);
	int		 rc;

	Assert(len > 0);

	p.proto.nuls[0] = p.proto.nuls[1] = '\0';
	p.proto.pid = MyProcPid;

	/* write all but the last chunk */
	while (len > PIPE_MAX_PAYLOAD)
	{
		p.proto.is_last = 'f';
		p.proto.len = PIPE_MAX_PAYLOAD;
		memcpy(p.proto.data, data, PIPE_MAX_PAYLOAD);
		rc = write(fd, &p, PIPE_HEADER_SIZE + PIPE_MAX_PAYLOAD);
		(void) rc;
		data += PIPE_MAX_PAYLOAD;
		len -= PIPE_MAX_PAYLOAD;
	}

	/* write the last chunk */
	p.proto.is_last = 't';
	p.proto.len = len;
	memcpy(p.proto.data, data, len);
	rc = write(fd, &p, PIPE_HEADER_SIZE + len);
	(void) rc;
}

static void
setup_formatted_log_time(void)
{
	struct timeval tv;
	pg_time_t   stamp_time;
	char		msbuf[8];

	gettimeofday(&tv, NULL);
	stamp_time = (pg_time_t) tv.tv_sec;
	time_stamp_epoch = (float)(tv.tv_usec / 1000000.0);
	time_stamp_epoch += (float)stamp_time;
	/*
	 * Note: we expect that guc.c will ensure that log_timezone is set up (at
	 * least with a minimal GMT value) before Log_line_prefix can become
	 * nonempty or CSV mode can be selected.
	 */
	pg_strftime(log_time, LOG_TIMESTAMP_LEN,
				/* leave room for milliseconds... */
				"%Y-%m-%dT%H:%M:%SZ%z",
				pg_localtime(&stamp_time, log_timezone));

	/* 'paste' milliseconds into place... */
	sprintf(msbuf, ".%03d", (int) (tv.tv_usec / 1000));
	//strncpy(log_time + 19, msbuf, 4);
	insert_substring(log_time, msbuf, 20);
	//strncpy(log_time + 23, zonebuf, 5);
}

/*
 * appendJSONLiteral
 * Append to given StringInfo a JSON with a given key and a value
 * not yet made literal.
 */
static void
appendJSONLiteral(StringInfo buf, char *key, char *value, bool is_comma)
{
	StringInfoData literal_json;

	initStringInfo(&literal_json);
	Assert(key && value);

	/*
	 * Call in-core function able to generate wanted strings, there is
	 * no need to reinvent the wheel.
	 */
	escape_json(&literal_json, value);

	/* Now append the field */
	appendStringInfo(buf, "%s:%s", key, literal_json.data);

	/* Add comma if necessary */
	if (is_comma)
		//appendStringInfoChar(buf, ',');

	/* Clean up */
	pfree(literal_json.data);
}

/*
 * write_jsonlog
 * Write logs in json format.
 */
struct timeval tve;
char hostname[1024];
struct ifaddrs *id;
int val;

static void
write_jsonlog(ErrorData *edata)
{
	StringInfoData	buf;
  StringInfoData  composeBuf;
	TransactionId	txid = GetTopTransactionIdIfAny();

	initStringInfo(&buf);
	initStringInfo(&composeBuf);

	gettimeofday(&tve, NULL);
	gethostname(hostname, 1024);
	val = getifaddrs(&id);

  /* Initialize string for JSON format */
  appendStringInfoChar(&composeBuf, '{');

	/* Timestamp */
	setup_formatted_log_time();
	appendStringInfo(&composeBuf, "\"@fields\": { \"timestamp_raw\":\"%s\", ", log_time);
	appendStringInfo(&composeBuf, "\"timestamp\": %.03f, ", time_stamp_epoch);
	appendStringInfo(&composeBuf, "\"timestamp_epoch_sec\": %d, ", (int) tve.tv_sec);
	appendStringInfo(&composeBuf, "\"timestamp_epoch_usec\": %d, ", (int) tve.tv_usec);

	/* Error severity */
	appendStringInfo(&composeBuf, "\"error_severity\":\"%s\", ", (char *) error_severity(edata->elevel));

	/* Source Log */
	appendStringInfo(&composeBuf, "\"source_name\": \"postgresql\" , ");

	/* Source Hostname */
	appendStringInfo(&composeBuf, "\"source_hostname\": \"%s\" , ", hostname);

	/* Source PID */
	appendStringInfo(&composeBuf, "\"source_pid\": \"%d\" , ", MyProcPid);

	/* Username */
	if (MyProcPort)
		appendStringInfo(&composeBuf, "\"source_user\":\"%s\", ", MyProcPort->user_name);

	/* Database name */
	if (MyProcPort)
		appendStringInfo(&composeBuf, "\"source_dbname\":\"%s\", ", MyProcPort->database_name);

	/* Remote host and port */
	if (MyProcPort && MyProcPort->remote_host)
	{
		appendStringInfo(&composeBuf, "\"remote_host\":\"%s\", ", MyProcPort->remote_host);

    if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0')
			appendStringInfo(&composeBuf, "\"remote_port\":\"%s\", ", MyProcPort->remote_port);
	}

	/* Session id */
	if (MyProcPid != 0)
    appendStringInfo(&composeBuf, "\"session_id\":\"%lx.%x\", ", (long) MyStartTime, MyProcPid);

	/* Virtual transaction id */
	/* keep VXID format in sync with lockfuncs.c */
	if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
    appendStringInfo(&composeBuf, "\"vxid\":\"%d/%u\", ", MyProc->backendId, MyProc->lxid);

	/* Transaction id */
	if (txid != InvalidTransactionId)
    appendStringInfo(&composeBuf, "\"txid\":\"%u\",", GetTopTransactionIdIfAny());

	/* SQL state code */
	if (edata->sqlerrcode != ERRCODE_SUCCESSFUL_COMPLETION)
		appendStringInfo(&composeBuf, "\"state_code\":\"%s\", ", unpack_sql_state(edata->sqlerrcode));

	/* Error detail or Error detail log */
	if (edata->detail_log)
		appendStringInfo(&composeBuf, "\"detail\":\"%s\", ", edata->detail_log);
	else if (edata->detail)
		appendStringInfo(&composeBuf, "\"detail\":\"%s\", ", edata->detail);

	/* Error Hint */
	if (edata->hint)
		appendStringInfo(&composeBuf, "\"hint\":\"%s\", ", edata->hint);

	/* Internal Query */
	if (edata->internalquery)
		appendStringInfo(&composeBuf, "\"internal_query\":\"%s\", ", edata->internalquery);

	/* Error Context */
	if (edata->context)
		appendStringInfo(&composeBuf, "\"context\":\"%s\", ", edata->context);

	/* File Error Location */
	if (Log_error_verbosity >= PGERROR_VERBOSE)
	{
		StringInfoData msgbuf;
		initStringInfo(&msgbuf);

		if (edata->funcname && edata->filename)
			appendStringInfo(&msgbuf, "%s, %s:%d",
							 edata->funcname, edata->filename,
							 edata->lineno);
		else if (edata->filename)
			appendStringInfo(&msgbuf, "%s:%d",
							 edata->filename, edata->lineno);

		appendStringInfo(&composeBuf, "\"log_location\":\"%s\", ", msgbuf.data);
		pfree(msgbuf.data);
	}

	/* Client */
	if (application_name && application_name[0] != '\0')
		appendStringInfo(&composeBuf, "\"client\":\"%s\", ", application_name);

	/* SQL Query Result */
	appendJSONLiteral(&composeBuf, "\"sql_result\"", edata->message, true);

  /* Finish string */
	appendStringInfoChar(&composeBuf, '}');
	appendStringInfoChar(&composeBuf, '}');

	/* Add new line for pretty format */
	appendStringInfoChar(&composeBuf, '\n');

	/* Block logging on server, priority is given to JSON format */
	edata->output_to_server = false;

	/* If in the syslogger process, try to write messages direct to file */
	if (am_syslogger)
		write_syslogger_file(composeBuf.data, composeBuf.len, LOG_DESTINATION_STDERR);
	else
		write_pipe_chunks(composeBuf.data, composeBuf.len);

	/* Cleanup */
	pfree(buf.data);
	pfree(composeBuf.data);
}

/*
 * _PG_init
 * Entry point loading hooks
 */
void
_PG_init(void)
{
	prev_log_hook = emit_log_hook;
	emit_log_hook = write_jsonlog;
}

/*
 * _PG_fini
 * Exit point unloading hooks
 */
void
_PG_fini(void)
{
	emit_log_hook = prev_log_hook;
}
