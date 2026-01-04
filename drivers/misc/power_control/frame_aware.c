// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/types.h>

extern int pc_request_temp_boost(unsigned int khz, unsigned int ms);

#define FRAME_NS              16666666ULL
#define FRAME_MISS_NS         20000000ULL
#define FLING_INTERVAL_NS     8000000ULL

#define BOOST_IDLE            0
#define BOOST_TAP             10
#define BOOST_SCROLL          20
#define BOOST_FLING           30
#define BOOST_MISS_MAX        50
#define BOOST_STEP_MAX        10

#define KHZ_IDLE              0
#define KHZ_TAP               300000
#define KHZ_SCROLL            600000
#define KHZ_FLING             900000
#define KHZ_MISS_MAX          1200000

#define MS_TAP                30
#define MS_SCROLL             50
#define MS_FLING              80
#define MS_MISS_MAX           120

enum frame_state {
	STATE_IDLE = 0,
	STATE_TAP,
	STATE_SCROLL,
	STATE_FLING,
};

struct frame_ctx {
	spinlock_t lock;
	enum frame_state state;
	u64 last_frame_ns;
	u64 last_input_ns;
	int cur_boost;
	int target_boost;
	bool display_on;
	struct hrtimer idle_timer;
};

static struct frame_ctx g_ctx;

static inline int clamp_boost(int cur, int target)
{
	if (target > cur + BOOST_STEP_MAX)
		return cur + BOOST_STEP_MAX;
	if (target < cur - BOOST_STEP_MAX)
		return cur - BOOST_STEP_MAX;
	return target;
}

static inline void apply_boost(int boost)
{
	switch (boost) {
	case BOOST_TAP:
		pc_request_temp_boost(KHZ_TAP, MS_TAP);
		break;
	case BOOST_SCROLL:
		pc_request_temp_boost(KHZ_SCROLL, MS_SCROLL);
		break;
	case BOOST_FLING:
		pc_request_temp_boost(KHZ_FLING, MS_FLING);
		break;
	case BOOST_MISS_MAX:
		pc_request_temp_boost(KHZ_MISS_MAX, MS_MISS_MAX);
		break;
	default:
		break;
	}
}

static void update_boost_locked(void)
{
	int next = clamp_boost(g_ctx.cur_boost, g_ctx.target_boost);
	g_ctx.cur_boost = next;
	apply_boost(next);
}

static enum hrtimer_restart frame_idle_timeout(struct hrtimer *t)
{
	spin_lock(&g_ctx.lock);
	g_ctx.state = STATE_IDLE;
	g_ctx.target_boost = BOOST_IDLE;
	g_ctx.cur_boost = BOOST_IDLE;
	spin_unlock(&g_ctx.lock);
	return HRTIMER_NORESTART;
}

static void frame_commit_locked(u64 now)
{
	if (g_ctx.last_frame_ns &&
	    now - g_ctx.last_frame_ns > FRAME_MISS_NS)
		g_ctx.target_boost = BOOST_MISS_MAX;

	g_ctx.last_frame_ns = now;
	hrtimer_start(&g_ctx.idle_timer,
		      ns_to_ktime(FRAME_NS),
		      HRTIMER_MODE_REL);
}

static void frame_input_event(enum frame_state type)
{
	u64 now = ktime_get_ns();

	spin_lock(&g_ctx.lock);

	g_ctx.last_input_ns = now;
	g_ctx.state = type;

	switch (type) {
	case STATE_TAP:
		g_ctx.target_boost = BOOST_TAP;
		break;
	case STATE_SCROLL:
		g_ctx.target_boost = BOOST_SCROLL;
		break;
	case STATE_FLING:
		g_ctx.target_boost = BOOST_FLING;
		break;
	default:
		break;
	}

	frame_commit_locked(now);
	update_boost_locked();

	spin_unlock(&g_ctx.lock);
}

void frame_aware_on_input(bool is_down, bool is_move)
{
	u64 now = ktime_get_ns();

	if (!g_ctx.display_on)
		return;

	if (is_down) {
		frame_input_event(STATE_TAP);
		return;
	}

	if (is_move) {
		if (g_ctx.last_input_ns &&
		    now - g_ctx.last_input_ns < FLING_INTERVAL_NS)
			frame_input_event(STATE_FLING);
		else
			frame_input_event(STATE_SCROLL);
	}
}

void frame_aware_on_binder(void)
{
	spin_lock(&g_ctx.lock);
	frame_commit_locked(ktime_get_ns());
	update_boost_locked();
	spin_unlock(&g_ctx.lock);
}

void frame_aware_on_display(bool on)
{
	spin_lock(&g_ctx.lock);

	g_ctx.display_on = on;

	if (!on) {
		g_ctx.state = STATE_IDLE;
		g_ctx.cur_boost = BOOST_IDLE;
		g_ctx.target_boost = BOOST_IDLE;
		hrtimer_cancel(&g_ctx.idle_timer);
	}

	spin_unlock(&g_ctx.lock);
}

static int __init frame_aware_init(void)
{
	spin_lock_init(&g_ctx.lock);

	g_ctx.state = STATE_IDLE;
	g_ctx.cur_boost = BOOST_IDLE;
	g_ctx.target_boost = BOOST_IDLE;
	g_ctx.display_on = false;
	g_ctx.last_frame_ns = 0;
	g_ctx.last_input_ns = 0;

	hrtimer_init(&g_ctx.idle_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	g_ctx.idle_timer.function = frame_idle_timeout;

	pr_info("frame_aware: built-in initialized\n");
	return 0;
}

late_initcall(frame_aware_init);
