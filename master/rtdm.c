/*****************************************************************************
 *
 *  $Id$
 *
 *  Copyright (C) 2009-2010  Moehwald GmbH B. Benner
 *                     2011  IgH Andreas Stewering-Bone
 *                     2012  Florian Pose <fp@igh-essen.com>
 *
 *  This file is part of the IgH EtherCAT master.
 *
 *  The IgH EtherCAT master is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation; version 2 of the License.
 *
 *  The IgH EtherCAT master is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 *  Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with the IgH EtherCAT master. If not, see <http://www.gnu.org/licenses/>.
 *
 *  The license mentioned above concerns the source code only. Using the
 *  EtherCAT technology and brand is only permitted in compliance with the
 *  industrial property and similar rights of Beckhoff Automation GmbH.
 *
 ****************************************************************************/

/** \file
 * RTDM interface.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mman.h>

#include <rtdm/driver.h>

#include "master.h"
#include "ioctl.h"
#include "rtdm.h"

/** Set to 1 to enable device operations debugging.
 */
#define DEBUG 0

/****************************************************************************/

int ec_rtdm_open(struct rtdm_fd *, int);
void ec_rtdm_close(struct rtdm_fd *);
int ec_rtdm_ioctl(struct rtdm_fd *,unsigned int, void __user *);

#define RTSER_PROFILE_VER               3
#define RT_ETHERCAT_MASTER_MAX          3
static struct rtdm_driver ethercat_driver = {
        .profile_info           = RTDM_PROFILE_INFO(ethercat,
                                                    RTDM_CLASS_EXPERIMENTAL,
                                                    222,
                                                    RTSER_PROFILE_VER),
        .device_count           = RT_ETHERCAT_MASTER_MAX,
        .device_flags           = RTDM_NAMED_DEVICE | RTDM_EXCLUSIVE,
        .context_size           = sizeof(ec_rtdm_context_t),
        .ops = {
                .open           = ec_rtdm_open,
                .close          = ec_rtdm_close,
#ifdef EC_RTNET
                .ioctl_rt       = ec_rtdm_ioctl,
#else
                .ioctl_nrt      = ec_rtdm_ioctl,
#endif
        //        .read_rt        = rt_imx_uart_read,
        //        .write_rt       = rt_imx_uart_write,
        },   
};


/****************************************************************************/

/** Initialize an RTDM device.
 *
 * \return Zero on success, otherwise a negative error code.
 */
int ec_rtdm_dev_init(
        ec_rtdm_dev_t *rtdm_dev, /**< EtherCAT RTDM device. */
        ec_master_t *master /**< EtherCAT master. */
        )
{
    int ret;

    rtdm_dev->master = master;

    rtdm_dev->dev = kzalloc(sizeof(struct rtdm_device), GFP_KERNEL);
    if (!rtdm_dev->dev) {
        EC_MASTER_ERR(master, "Failed to reserve memory for RTDM device.\n");
        return -ENOMEM;
    }

    rtdm_dev->dev->label = "RT_EtherCat%d";
    rtdm_dev->dev->device_data = rtdm_dev; /* pointer to parent */
    rtdm_dev->dev->driver = &ethercat_driver;
    ret = rtdm_dev_register(rtdm_dev->dev);
    if (ret) {
        EC_MASTER_ERR(master, "Initialization of RTDM interface failed"
                " (return value %i).\n", ret);
        kfree(rtdm_dev->dev);
    }
    EC_MASTER_INFO(master, "Registering RTDM device %s.\n", rtdm_dev->dev->name);

    return ret;
}

/****************************************************************************/

/** Clear an RTDM device.
 */
void ec_rtdm_dev_clear(
        ec_rtdm_dev_t *rtdm_dev /**< EtherCAT RTDM device. */
        )
{
    EC_MASTER_INFO(rtdm_dev->master, "Unregistering RTDM device %s.\n",
            rtdm_dev->dev->name);
    rtdm_dev_unregister(rtdm_dev->dev);
    kfree(rtdm_dev->dev);
}

/****************************************************************************/

/** Driver open.
 *
 * \return Always zero (success).
 */
int ec_rtdm_open(
	struct rtdm_fd *fd,
        int oflags /**< Open flags. */
        )
{
    ec_rtdm_context_t *ctx = rtdm_fd_to_private(fd);

    ctx->rtdm_fd = fd;
    ctx->ioctl_ctx.writable = oflags & O_WRONLY || oflags & O_RDWR;
    ctx->ioctl_ctx.requested = 0;
    ctx->ioctl_ctx.process_data = NULL;
    ctx->ioctl_ctx.process_data_size = 0;

#if DEBUG
    ec_rtdm_dev_t *rtdm_dev = (ec_rtdm_dev_t *)rtdm_fd_device(fd)->device_data;
    EC_MASTER_INFO(rtdm_dev->master, "RTDM device %s opened.\n",
            rtdm_dev->dev->name);
#endif
    return 0;
}

/****************************************************************************/

/** Driver close.
 *
 * \return Always zero (success).
 */
void ec_rtdm_close( struct rtdm_fd *fd )
{
    ec_rtdm_context_t *ctx = rtdm_fd_to_private(fd);
    ec_rtdm_dev_t *rtdm_dev = (ec_rtdm_dev_t *)rtdm_fd_device(fd)->device_data;

    if (ctx->ioctl_ctx.requested) {
        ecrt_release_master(rtdm_dev->master);
	}
    ctx->rtdm_fd = NULL;
#if DEBUG
    EC_MASTER_INFO(rtdm_dev->master, "RTDM device %s closed.\n",
            rtdm_dev->dev->name);
#endif
}

/****************************************************************************/

/** Driver ioctl.
 *
 * \return ioctl() return code.
 */
int ec_rtdm_ioctl(
        struct rtdm_fd *fd,
        unsigned int request, /**< Request. */
        void __user *arg /**< Argument. */
        )
{
    ec_rtdm_context_t *ctx = rtdm_fd_to_private(fd);
    ec_rtdm_dev_t *rtdm_dev = (ec_rtdm_dev_t *)rtdm_fd_device(fd)->device_data;

#if DEBUG
    EC_MASTER_INFO(rtdm_dev->master, "ioctl(request = %u, ctl = %02x)"
            " on RTDM device %s.\n", request, _IOC_NR(request),
            rtdm_dev->dev->name);
#endif
    return ec_ioctl_rtdm(rtdm_dev->master, &ctx->ioctl_ctx, request, arg);
}

/****************************************************************************/

/** Memory-map process data to user space.
 *
 * \return Zero on success, otherwise a negative error code.
 */
int ec_rtdm_mmap(
        ec_ioctl_context_t *ioctl_ctx, /**< Context. */
        void **user_address /**< Userspace address. */
        )
{
    ec_rtdm_context_t *ctx =
        container_of(ioctl_ctx, ec_rtdm_context_t, ioctl_ctx);
    int ret;

    ret = rtdm_mmap_to_user(ctx->rtdm_fd,
            ioctl_ctx->process_data, ioctl_ctx->process_data_size,
            PROT_READ | PROT_WRITE,
            user_address,
            NULL, NULL);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/****************************************************************************/
