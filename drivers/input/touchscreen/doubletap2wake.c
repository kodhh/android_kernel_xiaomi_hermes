/*
 * drivers/input/touchscreen/doubletap2wake.c
 *
 *
 * Copyright (c) 2013, Dennis Rassmann <showp1984@gmail.com>
 * Copyright (c) 2015, Vineeth Raj <contact.twn@openmailbox.org>
 * Copyright (c) 2015, Swapnil Solanki <swapnil133609@gmail.com>
 * Copyright (c) 2015, Levin Calado <levincalado@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/input.h>
#include <linux/hrtimer.h>
#include <asm-generic/cputime.h>
#include <linux/wakelock.h>
#include <linux/input/doubletap2wake.h>

/* uncomment since no touchscreen defines android touch, do that here */
//#define ANDROID_TOUCH_DECLARED

#define WAKE_HOOKS_DEFINED

#ifndef WAKE_HOOKS_DEFINED
#ifndef CONFIG_HAS_EARLYSUSPEND
#include <linux/lcd_notify.h>
#else
#include <linux/earlysuspend.h>
#endif
#endif

/* if Sweep2Wake is compiled it will already have taken care of this */
#ifdef CONFIG_TOUCHSCREEN_SWEEP2WAKE
#define ANDROID_TOUCH_DECLARED
#endif

#ifdef CONFIG_POCKETMOD
#include <linux/pocket_mod.h>
#endif

/* Version, author, desc, etc */
#define DRIVER_AUTHOR "Dennis Rassmann <showp1984@gmail.com>"
#define DRIVER_DESCRIPTION "Doubletap2wake for almost any device"
#define DRIVER_VERSION "1.0"
#define LOGTAG "[doubletap2wake]: "

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPLv2");

/* Tuneables */
#define DT2W_DEBUG         0
#define DT2W_DEFAULT       0

#define DT2W_PWRKEY_DUR   60
#define DT2W_FEATHER      50
#define DT2W_TIME        600

/* Resources */
int dt2w_switch = DT2W_DEFAULT;
static struct wake_lock dt2w_wakelock;

static void dt2w_wake_lock_sync(void)
{
	if (dt2w_switch) {
		if (!wake_lock_active(&dt2w_wakelock))
			wake_lock(&dt2w_wakelock);
	} else if (wake_lock_active(&dt2w_wakelock)) {
		wake_unlock(&dt2w_wakelock);
	}
}
static cputime64_t tap_time_pre = 0;
static int touch_x = 0, touch_y = 0, touch_nr = 0, x_pre = 0, y_pre = 0;
static bool touch_x_called = false, touch_y_called = false, touch_cnt = true;
static bool exec_count = true;
bool dt2w_scr_suspended = false;
#ifndef WAKE_HOOKS_DEFINED
#ifndef CONFIG_HAS_EARLYSUSPEND
static struct notifier_block dt2w_lcd_notif;
#endif
#endif
static struct input_dev * doubletap2wake_pwrdev;
static DEFINE_MUTEX(pwrkeyworklock);
static struct workqueue_struct *dt2w_input_wq;
static struct work_struct dt2w_input_work;

/* PowerKey setter */
void doubletap2wake_setdev(struct input_dev * input_device) {
	doubletap2wake_pwrdev = input_device;
	printk(LOGTAG"set doubletap2wake_pwrdev: %s\n", doubletap2wake_pwrdev->name);
}

/*
 * Screen state hooks. On Android 10 SystemSuspend suspends via
 * /sys/power/autosleep -> pm_suspend() directly, so the earlysuspend chain
 * (and with it tpd_suspend/tpd_resume) never runs and dt2w_scr_suspended is
 * never updated. The reliable screen-off/on signal is the display driver's
 * suspend/resume (see primary_display.c). Keep the FT5346 in normal active
 * mode and use the software double-tap detection in dt2w_input_event() -- the
 * chip's low-power hardware gesture never reports a double tap (0x24) on this
 * part. The touch EINT wakes the SoC briefly for the touch bursts; two taps
 * within DT2W_TIME then inject KEY_POWER from the kernel.
 */
void doubletap2wake_screen_off(void)
{
	dt2w_scr_suspended = true;
}
EXPORT_SYMBOL(doubletap2wake_screen_off);

void doubletap2wake_screen_on(void)
{
	dt2w_scr_suspended = false;
}
EXPORT_SYMBOL(doubletap2wake_screen_on);

/* Read cmdline for dt2w */
static int __init read_dt2w_cmdline(char *dt2w)
{
	if (strcmp(dt2w, "1") == 0) {
		pr_info("[cmdline_dt2w]: DoubleTap2Wake enabled. | dt2w='%s'\n", dt2w);
		dt2w_switch = 1;
	} else if (strcmp(dt2w, "0") == 0) {
		pr_info("[cmdline_dt2w]: DoubleTap2Wake disabled. | dt2w='%s'\n", dt2w);
		dt2w_switch = 0;
	} else {
		pr_info("[cmdline_dt2w]: No valid input found. Going with default: | dt2w='%u'\n", dt2w_switch);
	}
	return 1;
}
__setup("dt2w=", read_dt2w_cmdline);

/* reset on finger release */
static void doubletap2wake_reset(void) {
	exec_count = true;
	touch_nr = 0;
	tap_time_pre = 0;
	x_pre = 0;
	y_pre = 0;
}

/* PowerKey work func */
static void doubletap2wake_presspwr(struct work_struct * doubletap2wake_presspwr_work) {
	if (!mutex_trylock(&pwrkeyworklock))
		return;
	input_event(doubletap2wake_pwrdev, EV_KEY, KEY_POWER, 1);
	input_event(doubletap2wake_pwrdev, EV_SYN, 0, 0);
	msleep(DT2W_PWRKEY_DUR);
	input_event(doubletap2wake_pwrdev, EV_KEY, KEY_POWER, 0);
	input_event(doubletap2wake_pwrdev, EV_SYN, 0, 0);
	msleep(DT2W_PWRKEY_DUR);
	mutex_unlock(&pwrkeyworklock);
	return;
}
static DECLARE_WORK(doubletap2wake_presspwr_work, doubletap2wake_presspwr);

/* PowerKey trigger */
static void doubletap2wake_pwrtrigger(void) {
	schedule_work(&doubletap2wake_presspwr_work);
	return;
}

/* Direct wake trigger for the FT5346 hardware double-tap gesture: the touch
 * controller detects the double tap itself in low-power mode (just like the
 * proximity sensor), so we bypass the input-event heuristics and act straight
 * from the touch driver. */
void doubletap2wake_trigger(void) {
	if (dt2w_switch && dt2w_scr_suspended)
		doubletap2wake_pwrtrigger();
	return;
}
EXPORT_SYMBOL(doubletap2wake_trigger);

/* unsigned */
static unsigned int calc_feather(int coord, int prev_coord) {
	int calc_coord = 0;
	calc_coord = coord-prev_coord;
	if (calc_coord < 0)
		calc_coord = calc_coord * (-1);
	return calc_coord;
}

/* init a new touch */
static void new_touch(int x, int y) {
	tap_time_pre = ktime_to_ms(ktime_get());
	x_pre = x;
	y_pre = y;
	touch_nr++;
}

/* Doubletap2wake main function */
static void detect_doubletap2wake(int x, int y, bool st)
{
	bool single_touch = st;
#if DT2W_DEBUG
	pr_info(LOGTAG"x,y(%4d,%4d) single:%s\n",
		x, y, (single_touch) ? "true" : "false");
#endif
	if ((single_touch) && (dt2w_switch > 0) && (exec_count) && (touch_cnt)) {
		touch_cnt = false;
		if (touch_nr == 0) {
			new_touch(x, y);
		} else if (touch_nr == 1) {
			if ((calc_feather(x, x_pre) < DT2W_FEATHER) &&
			    (calc_feather(y, y_pre) < DT2W_FEATHER) &&
			    ((ktime_to_ms(ktime_get())-tap_time_pre) < DT2W_TIME))
				touch_nr++;
			else {
				doubletap2wake_reset();
				new_touch(x, y);
			}
		} else {
			doubletap2wake_reset();
			new_touch(x, y);
		}
		if ((touch_nr > 1)) {
			pr_info(LOGTAG"ON\n");
			exec_count = false;
			doubletap2wake_pwrtrigger();
			doubletap2wake_reset();
		}
	}
}

static void dt2w_input_callback(struct work_struct *unused) {
	
	#ifdef CONFIG_POCKETMOD
	if (device_is_pocketed()){
		return;
	}
	else
	#endif
	detect_doubletap2wake(touch_x, touch_y, true);

	return;
}

static void dt2w_input_event(struct input_handle *handle, unsigned int type,
				unsigned int code, int value) {
#if DT2W_DEBUG
	pr_info("doubletap2wake: code: %s|%u, val: %i\n",
		((code==ABS_MT_POSITION_X) ? "X" :
		(code==ABS_MT_POSITION_Y) ? "Y" :
		((code==ABS_MT_TRACKING_ID)||
			(code==330)) ? "ID" : "undef"), code, value);
#endif
	if (!dt2w_scr_suspended)
		return;

	if (code == ABS_MT_SLOT) {
		doubletap2wake_reset();
		return;
	}

	/*
	 * '330'? Many touch panels are 'broken' in the sense of not following the
	 * multi-touch protocol given in Documentation/input/multi-touch-protocol.txt.
	 * According to the docs, touch panels using the type B protocol must send in
	 * a ABS_MT_TRACKING_ID event after lifting the contact in the first slot.
	 * This should in the flow of events, help us set the necessary doubletap2wake
	 * variable and proceed as per the algorithm.
	 *
	 * This however is not the case with various touch panel drivers, and hence
	 * there is no reliable way of tracking ABS_MT_TRACKING_ID on such panels.
	 * Some of the panels however do track the lifting of contact, but with a
	 * different event code, and a different event value.
	 *
	 * So, add checks for those event codes and values to keep the algo flow.
	 *
	 * synaptics_s3203 => code: 330; val: 0
	 *
	 * Note however that this is not possible with panels like the CYTTSP3 panel
	 * where there are no such events being reported for the lifting of contacts
	 * though i2c data has a ABS_MT_TRACKING_ID or equivalent event variable
	 * present. In such a case, make sure the touch_cnt variable is publicly
	 * available for modification.
	 *
	 */
	if ((code == ABS_MT_TRACKING_ID && value == -1) || (code == 330 && value == 0)) {
		touch_cnt = true;
		return;
	}

	if (code == ABS_MT_POSITION_X) {
		touch_x = value;
		touch_x_called = true;
	}

	if (code == ABS_MT_POSITION_Y) {
		touch_y = value;
		touch_y_called = true;
	}

	if (touch_x_called || touch_y_called) {
		touch_x_called = false;
		touch_y_called = false;
		queue_work_on(0, dt2w_input_wq, &dt2w_input_work);
	}
}

static int input_dev_filter(struct input_dev *dev) {
	if (strstr(dev->name, "touch")||
			strstr(dev->name, "mtk-tpd")) {
		return 0;
	} else {
		return 1;
	}
}

static int dt2w_input_connect(struct input_handler *handler,
				struct input_dev *dev, const struct input_device_id *id) {
	struct input_handle *handle;
	int error;

	if (input_dev_filter(dev))
		return -ENODEV;

	handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "dt2w";

	error = input_register_handle(handle);
	if (error)
		goto err2;

	error = input_open_device(handle);
	if (error)
		goto err1;

	return 0;
err1:
	input_unregister_handle(handle);
err2:
	kfree(handle);
	return error;
}

static void dt2w_input_disconnect(struct input_handle *handle) {
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static const struct input_device_id dt2w_ids[] = {
	{ .driver_info = 1 },
	{ },
};

static struct input_handler dt2w_input_handler = {
	.event		= dt2w_input_event,
	.connect	= dt2w_input_connect,
	.disconnect	= dt2w_input_disconnect,
	.name		= "dt2w_inputreq",
	.id_table	= dt2w_ids,
};

#ifndef WAKE_HOOKS_DEFINED
#ifndef CONFIG_HAS_EARLYSUSPEND
static int lcd_notifier_callback(struct notifier_block *this,
				unsigned long event, void *data)
{
	switch (event) {
	case LCD_EVENT_ON_END:
		dt2w_scr_suspended = false;
		break;
	case LCD_EVENT_OFF_END:
		dt2w_scr_suspended = true;
		break;
	default:
		break;
	}

	return 0;
}
#else
static void dt2w_early_suspend(struct early_suspend *h) {
	dt2w_scr_suspended = true;
}

static void dt2w_late_resume(struct early_suspend *h) {
	dt2w_scr_suspended = false;
}

static struct early_suspend dt2w_early_suspend_handler = {
	.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN,
	.suspend = dt2w_early_suspend,
	.resume = dt2w_late_resume,
};
#endif
#endif

/*
 * SYSFS stuff below here
 */
static ssize_t dt2w_doubletap2wake_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	size_t count = 0;

	count += sprintf(buf, "%d\n", dt2w_switch);

	return count;
}

static ssize_t dt2w_doubletap2wake_dump(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	unsigned int val;

	err = kstrtouint(buf, 10, &val);
	if (err)
		return count;

	dt2w_switch = val ? 1 : 0;
	dt2w_wake_lock_sync();

	return count;
}

static DEVICE_ATTR(doubletap2wake, (S_IWUSR|S_IRUGO|S_IROTH|S_IWOTH),
	dt2w_doubletap2wake_show, dt2w_doubletap2wake_dump);

/* Direct gesture-mode control for userspace (powerhal / manual test).
 * Writing 1 arms the FT5346 low-power hardware double-tap detection
 * immediately (and marks the screen as off), writing 0 leaves it. Keeps
 * dt2w_scr_suspended in sync so a detected double-tap wakes the device. */
static ssize_t dt2w_gesture_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	size_t count = 0;

	count += sprintf(buf, "%d\n", dt2w_scr_suspended ? 1 : 0);

	return count;
}

static ssize_t dt2w_gesture_mode_dump(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	unsigned int val;

	err = kstrtouint(buf, 10, &val);
	if (err)
		return count;

	if (val)
		doubletap2wake_screen_off();
	else
		doubletap2wake_screen_on();

	return count;
}

static DEVICE_ATTR(gesture_mode, (S_IWUSR|S_IRUGO|S_IROTH|S_IWOTH),
	dt2w_gesture_mode_show, dt2w_gesture_mode_dump);

static ssize_t dt2w_version_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	size_t count = 0;

	count += sprintf(buf, "%s\n", DRIVER_VERSION);

	return count;
}

static ssize_t dt2w_version_dump(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	return count;
}

static DEVICE_ATTR(doubletap2wake_version, (S_IWUSR|S_IRUGO),
	dt2w_version_show, dt2w_version_dump);

/*
 * INIT / EXIT stuff below here
 */
#ifdef ANDROID_TOUCH_DECLARED
extern struct kobject *android_touch_kobj;
#else
struct kobject *android_touch_kobj;
EXPORT_SYMBOL_GPL(android_touch_kobj);
#endif

/*
 * The touch controller (FT5346) exposes no KEY_POWER, so inject the wake
 * key on a dedicated virtual input device instead of the touch device.
 */
static int doubletap2wake_pwrdev_init(void)
{
	doubletap2wake_pwrdev = input_allocate_device();
	if (!doubletap2wake_pwrdev)
		return -ENOMEM;

	doubletap2wake_pwrdev->name = "doubletap2wake_keypad";
	doubletap2wake_pwrdev->phys = "doubletap2wake/input0";
	doubletap2wake_pwrdev->id.bustype = BUS_HOST;
	doubletap2wake_pwrdev->id.vendor = 0x0001;
	doubletap2wake_pwrdev->id.product = 0x0001;
	doubletap2wake_pwrdev->id.version = 0x0100;

	set_bit(EV_KEY, doubletap2wake_pwrdev->evbit);
	set_bit(KEY_POWER, doubletap2wake_pwrdev->keybit);

	if (input_register_device(doubletap2wake_pwrdev)) {
		input_free_device(doubletap2wake_pwrdev);
		doubletap2wake_pwrdev = NULL;
		return -ENODEV;
	}

	return 0;
}

static int __init doubletap2wake_init(void)
{
	int rc = 0;

	rc = doubletap2wake_pwrdev_init();
	if (rc)
		pr_err("%s: Failed to register pwrdev\n", __func__);

	dt2w_input_wq = create_workqueue("dt2wiwq");
	if (!dt2w_input_wq) {
		pr_err("%s: Failed to create dt2wiwq workqueue\n", __func__);
		return -EFAULT;
	}
	INIT_WORK(&dt2w_input_work, dt2w_input_callback);
	rc = input_register_handler(&dt2w_input_handler);
	if (rc)
		pr_err("%s: Failed to register dt2w_input_handler\n", __func__);

	wake_lock_init(&dt2w_wakelock, WAKE_LOCK_SUSPEND, "dt2w_keepawake");
	dt2w_wake_lock_sync();

#ifndef WAKE_HOOKS_DEFINED
#ifndef CONFIG_HAS_EARLYSUSPEND
	dt2w_lcd_notif.notifier_call = lcd_notifier_callback;
	if (lcd_register_client(&dt2w_lcd_notif) != 0) {
		pr_err("%s: Failed to register lcd callback\n", __func__);
	}
#else
	register_early_suspend(&dt2w_early_suspend_handler);
#endif
#endif

#ifndef ANDROID_TOUCH_DECLARED
	android_touch_kobj = kobject_create_and_add("android_touch", NULL) ;
	if (android_touch_kobj == NULL) {
		pr_warn("%s: android_touch_kobj create_and_add failed\n", __func__);
	}
#endif
	rc = sysfs_create_file(android_touch_kobj, &dev_attr_doubletap2wake.attr);
	if (rc) {
		pr_warn("%s: sysfs_create_file failed for doubletap2wake\n", __func__);
	}
	rc = sysfs_create_file(android_touch_kobj, &dev_attr_doubletap2wake_version.attr);
	if (rc) {
		pr_warn("%s: sysfs_create_file failed for doubletap2wake_version\n", __func__);
	}
	rc = sysfs_create_file(android_touch_kobj, &dev_attr_gesture_mode.attr);
	if (rc) {
		pr_warn("%s: sysfs_create_file failed for gesture_mode\n", __func__);
	}

	return 0;
}

static void __exit doubletap2wake_exit(void)
{
#ifndef ANDROID_TOUCH_DECLARED
	kobject_del(android_touch_kobj);
#endif
#ifndef WAKE_HOOKS_DEFINED
#ifndef CONFIG_HAS_EARLYSUSPEND
	lcd_unregister_client(&dt2w_lcd_notif);
#endif
#endif
	if (doubletap2wake_pwrdev) {
		input_unregister_device(doubletap2wake_pwrdev);
		doubletap2wake_pwrdev = NULL;
	}
	wake_unlock(&dt2w_wakelock);
	wake_lock_destroy(&dt2w_wakelock);
	input_unregister_handler(&dt2w_input_handler);
	destroy_workqueue(dt2w_input_wq);
	return;
}

module_init(doubletap2wake_init);
module_exit(doubletap2wake_exit);
