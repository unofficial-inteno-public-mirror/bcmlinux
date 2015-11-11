#if defined(CONFIG_BCM_KF_ARM_BCM963XX)
/*
<:copyright-BRCM:2013:DUAL/GPL:standard

   Copyright (c) 2013 Broadcom Corporation
   All Rights Reserved

Unless you and Broadcom execute a separate written software license
agreement governing use of this software, this software is licensed
to you under the terms of the GNU General Public License version 2
(the "GPL"), available at http://www.broadcom.com/licenses/GPLv2.php,
with the following added to such license:

   As a special exception, the copyright holders of this software give
   you permission to link this software with independent modules, and
   to copy and distribute the resulting executable under terms of your
   choice, provided that you also meet, for each linked independent
   module, the terms and conditions of the license of that module.
   An independent module is a module which is not derived from this
   software.  The special exception does not apply to any modifications
   of the software.

Not withstanding the above, under no circumstances may you combine
this software in any way with any other Broadcom software provided
under a license other than the GPL, without Broadcom's express prior
written consent.

:>
*/

/*
 * Broadcom ARM BSP
 * Internal API declarations
 */


#ifndef __PLAT_BSP_H
#define __PLAT_BSP_H

struct clk;

void __init soc_fixup(void);
void __init soc_map_io(void);
void __init soc_init_clock(void);
void __init soc_init_irq(void);
void __init soc_init_early(void);
void __init soc_add_devices(void);
void __init soc_init_timer(void);

#endif /* __PLAT_BSP_H */
#endif /* CONFIG_BCM_KF_ARM_BCM963XX */
