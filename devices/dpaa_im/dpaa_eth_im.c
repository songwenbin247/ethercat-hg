/*
 * Copyright 2009-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018 NXP Semiconductor, Inc.
 *  <alan.wang@nxp.com>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

/******************************************************************************
 @File          dpaa_eth_im.c

 @Description   DPAA1 FMAN independent mode Ethernet driver implementation 
*//***************************************************************************/
#include <linux/device.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/string.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_platform.h>
#include <linux/of_net.h>
#include <linux/of_irq.h>
#include <linux/ethtool.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/crc32.h>

#include "dpaa_eth_im.h"
#include "fsl_memac.h"
#define MODULENAME "ec_dpaa_im"
#define RCTRL_INIT      (RCTRL_GRS | RCTRL_UPROM)
#define TCTRL_INIT      TCTRL_GTS
#define MACCFG1_INIT    MACCFG1_SOFT_RST

#define MACCFG2_INIT    (MACCFG2_PRE_LEN(0x7) | MACCFG2_LEN_CHECK | \
                         MACCFG2_PAD_CRC | MACCFG2_FULL_DUPLEX | \
                         MACCFG2_IF_MODE_NIBBLE)

/* MAXFRM - maximum frame length register */
#define MAXFRM_MASK      0x0000ffff

#define CONFIG_SYS_TBIPA_VALUE  8
#define JUMBO_FRAME_SIZE	9600

/* #define DEBUG */
#ifdef DEBUG
#define TRACE printk

static void fm_im_xmit_dump(struct sk_buff *skb)
{
    int i;

    TRACE("+++XMIT DATA DUMP(%x)+++\n", skb->len);
    TRACE("<0>""head: (len: 0x%x)\n", skb_headlen(skb));
    for(i = 0; i < skb_headlen(skb); i++) {
        if(i % 16 == 0)
            TRACE("\n%p:", skb->head + i);
        TRACE("%02x ", *(skb->head + i));

    }
    TRACE("data:(len:0x%x)\n",skb->data_len);
    for(i = 0; i < skb->data_len; i++) {
        if(i % 16 == 0)
            TRACE("\n%p:", skb->data + i);
        TRACE("%02x ", *(skb->data + i));
    }
}

static void fm_im_dump(struct net_device *dev)
{
    struct fm_im_private *priv;
    char *regs;
    u32 i;

    priv = netdev_priv(dev);
    regs = (char *)priv->reg;

    for(i = 0xE2000; i < 0xE3000; i++) {
        if(i % 32 == 0)
            TRACE("\n%06x:  ", i);
        TRACE("%02X ", regs[i]);
    }

    TRACE("size:%lx\n", sizeof(*(priv->reg)));
}
#else
#define TRACE(x...) do { ; } while(0)
#endif

static u32 fm_assign_risc(int port_id)
{
    u32 risc_sel, val;
    risc_sel = (port_id & 0x1) ? FMFPPRC_RISC2 : FMFPPRC_RISC1;
    val = (port_id << FMFPPRC_PORTID_SHIFT) & FMFPPRC_PORTID_MASK;
    val |= ((risc_sel << FMFPPRC_ORA_SHIFT) | risc_sel);

    return val;
}

static void bmi_rx_port_init(struct fm_im_private *priv, struct fm_bmi_rx_port *rx_port)
{
    int port_id, val;
    
    /* Set BMI to independent mode, Rx port disable */
    fm_im_write(&rx_port->fmbm_rcfg, FMBM_RCFG_IM);
    /* Clear FOF in IM case */
    fm_im_write(&rx_port->fmbm_rim, 0);
    /* Rx frame next engine -RISC */
    fm_im_write(&rx_port->fmbm_rfne, NIA_ENG_RISC | NIA_RISC_AC_IM_RX);
    /* Rx command attribute - no order, MR[3] = 1 */
    fm_im_clrbits(&rx_port->fmbm_rfca, FMBM_RFCA_ORDER | FMBM_RFCA_MR_MASK);
    fm_im_setbits(&rx_port->fmbm_rfca, FMBM_RFCA_MR(4));
    /* Enable Rx statistic counters */
    fm_im_write(&rx_port->fmbm_rstc, FMBM_RSTC_EN);
    /* Disable Rx performance counters */
    fm_im_write(&rx_port->fmbm_rpc, 0);

    /* Common BMI parameter for this port */ 
    /*
     * Set port parameters - FMBM_PP_x
     * max tasks 10G Rx/Tx=12, 1G Rx/Tx 4, others is 1
     * max dma 10G Rx/Tx=3, others is 1
     * set port FIFO size - FMBM_PFS_x
     * 4KB for all Rx and Tx ports
     */
    /* Rx 1G port */
    port_id = RX_PORT_1G_BASE + priv->num - 1;
    /* Max tasks=4, max dma=1, no extra */
    fm_im_write(&priv->reg->fm_bmi_common.fmbm_pp[port_id], FMBM_PP_MXT(4));
    /* FIFO size - 3KB, no extra */
    fm_im_write(&priv->reg->fm_bmi_common.fmbm_pfs[port_id], FMBM_PFS_IFSZ(0xf));

    val = fm_im_read(&priv->reg->fm_bmi_common.fmbm_pp[port_id]);
    TRACE("%s(): fmbm_pp[%d] = 0x%0x\n", __func__, port_id, val); 
    val = fm_im_read(&priv->reg->fm_bmi_common.fmbm_pfs[port_id]);
    TRACE("%s(): fmbm_pfs[%d] = 0x%0x\n", __func__, port_id, val); 
    /* IM mode, each even port ID to RISC#1, each odd port ID to RISC#2 */

    /* Rx 1G port */
    val = fm_assign_risc(port_id + 1);
    fm_im_write(&priv->reg->fm_fpm.fpmprc, val);
}

static void bmi_tx_port_init(struct fm_im_private *priv, struct fm_bmi_tx_port *tx_port)
{
    int port_id, val;
    
    /* Set BMI to independent mode, Tx port disable */
    fm_im_write(&tx_port->fmbm_tcfg, FMBM_TCFG_IM);

    /* Tx frame next engine -RISC */
    fm_im_write(&tx_port->fmbm_tfne, NIA_ENG_RISC | NIA_RISC_AC_IM_TX);
    fm_im_write(&tx_port->fmbm_tfene, NIA_ENG_RISC | NIA_RISC_AC_IM_TX);

    /* Tx command attribute - no order, MR[3] = 1 */
    fm_im_clrbits(&tx_port->fmbm_tfca, FMBM_TFCA_ORDER | FMBM_TFCA_MR_MASK);
    fm_im_setbits(&tx_port->fmbm_tfca, FMBM_TFCA_MR(4));

    /* Enable Tx statistic counters */
    fm_im_write(&tx_port->fmbm_tstc, FMBM_TSTC_EN);

    /* Disable Tx performance counters */
    fm_im_write(&tx_port->fmbm_tpc, 0);
    
    /* Common BMI parameter for this port */ 
    /*
     * set port parameters - FMBM_PP_x
     * max tasks 10G Rx/Tx=12, 1G Rx/Tx 4, others is 1
     * max dma 10G Rx/Tx=3, others is 1
     * set port FIFO size - FMBM_PFS_x
     * 4KB for all Rx and Tx ports
     */
    /* Tx 1G port FIFO size - 4KB, no extra */
    port_id = TX_PORT_1G_BASE + priv->num - 1;

    /* Max tasks=4, max dma=1, no extra */
    fm_im_write(&priv->reg->fm_bmi_common.fmbm_pp[port_id], FMBM_PP_MXT(4));

    /* FIFO size - 4KB, no extra */
    fm_im_write(&priv->reg->fm_bmi_common.fmbm_pfs[port_id], FMBM_PFS_IFSZ(0xf));

    val = fm_im_read(&priv->reg->fm_bmi_common.fmbm_pp[port_id]);
    TRACE("%s(): fmbm_pp[%d] = 0x%0x\n", __func__, port_id, val); 
    val = fm_im_read(&priv->reg->fm_bmi_common.fmbm_pfs[port_id]);
    TRACE("%s(): fmbm_pfs[%d] = 0x%0x\n", __func__, port_id, val); 

    /* IM mode, each even port ID to RISC#1, each odd port ID to RISC#2 */
    /* Tx 1G port */
    val = fm_assign_risc(port_id + 1);
    fm_im_write(&priv->reg->fm_fpm.fpmprc, val);
}

struct fm_muram muram[CONFIG_SYS_NUM_FMAN];
static void fm_init_muram(int fm_idx, void *muram_base)
{
    muram[fm_idx].base = muram_base;
    muram[fm_idx].size = CONFIG_SYS_FM_MURAM_SIZE;
    muram[fm_idx].alloc = muram_base + FM_MURAM_RES_SIZE;
    muram[fm_idx].top = muram_base + CONFIG_SYS_FM_MURAM_SIZE;
    TRACE("%s():%d: MURAM base 0x%p\n", __func__, __LINE__, muram_base);
}

void *fm_muram_base(int fm_idx)
{
    return muram[fm_idx].base;
}

void *fm_muram_alloc(int fm_idx, size_t size, u64 align)
{
    void *ret;
    u64 align_mask;
    size_t off;
    void *save;
    u32 *p;

    align_mask = align - 1;
    save = muram[fm_idx].alloc;

    off = (u64)save & align_mask;
    if (off != 0)
        muram[fm_idx].alloc += (align - off);
    off = size & align_mask;
    if (off != 0)
        size += (align - off);
    if ((muram[fm_idx].alloc + size) >= muram[fm_idx].top) {
        muram[fm_idx].alloc = save;
        printk("%s: Run out of ram.\n", __func__);
        return NULL;
    }

    ret = muram[fm_idx].alloc;
    muram[fm_idx].alloc += size;
    /* memset((void *)ret, 0, size); */
    for (p = (u32 *)ret; p < (u32 *)ret + size; p++) {
	*(u32 *)p = 0;
    }

    return ret;
}

static u16 muram_readw(u16 *addr)
{
    u64 base = (u64)addr & ~0x3UL;
    u32 val32 = fm_im_read((void *)base);
    int byte_pos;
    u16 ret;

    byte_pos = (u64)addr & 0x3UL;
    if (byte_pos)
        ret = (u16)(val32 & 0x0000ffff);
    else
        ret = (u16)((val32 & 0xffff0000) >> 16);

    return ret;
}

static void muram_writew(u16 *addr, u16 val)
{
    u64 base = (u64)addr & ~0x3;
    u32 org32 = fm_im_read((void *)base);
    u32 val32;
    int byte_pos;

    byte_pos = (u64)addr & 0x3UL;
    if (byte_pos)
        val32 = (org32 & 0xffff0000) | val;
    else
        val32 = (org32 & 0x0000ffff) | ((u32)val << 16);

    fm_im_write((void *)base, val32);
}

 /* De-active all the ports */
static void fman_de_active(struct ccsr_fman *reg)
{
    int i, port_id;
    struct fm_bmi_rx_port *port_reg;

    /* Rx 1G port */
    for (i = 0; i < MAX_NUM_RX_PORT_1G; i++) {
        port_id = RX_PORT_1G_BASE + i - 1;
        port_reg = (struct fm_bmi_rx_port *)&(reg->port[port_id].fm_bmi);
        fm_im_clrbits(&port_reg->fmbm_rcfg,FMBM_RCFG_EN);
    }

    /* Tx 1G port */
    for (i = 0; i < MAX_NUM_TX_PORT_1G; i++) {
        port_id = TX_PORT_1G_BASE + i - 1;
        port_reg = (struct fm_bmi_rx_port *)&(reg->port[port_id].fm_bmi);
        fm_im_clrbits(&port_reg->fmbm_rcfg,FMBM_RCFG_EN);
    }
}

/* Active return 1 */
static int fman_is_active(struct ccsr_fman *reg, int mac_idx)
{
    int port_id, val;
    struct fm_bmi_rx_port *port_reg;

    /* Rx 1G port */
    port_id = RX_PORT_1G_BASE + mac_idx - 1;
    port_reg = (struct fm_bmi_rx_port *)&(reg->port[port_id].fm_bmi);   
    val = fm_im_read(&port_reg->fmbm_rcfg);
    if (val & FMBM_RCFG_EN) {
        printk("%s: port_id = %d, val = 0x%0x\n", __func__, port_id+1, val);
        return 1;
    }
    
    /* Tx 1G p rt */
    port_id = TX_PORT_1G_BASE + mac_idx - 1;
    port_reg = (struct fm_bmi_rx_port *)&(reg->port[port_id].fm_bmi);   
    val = fm_im_read(&port_reg->fmbm_rcfg);
    if (val & FMBM_RCFG_EN) {
        printk("%s: port_id = %d, val = 0x%0x\n", __func__, port_id+1, val);
        return 1;
    }
 
    return 0;
}

static int fm_eth_rx_port_parameter_init(struct fm_im_private *priv)
{
    struct fm_port_global_pram *pram;
    u32 pram_page_offset;
    void *rx_bd_ring_base;
    struct fm_port_bd *rxbd;
    struct fm_port_qd *rxqd;
    struct fm_bmi_rx_port *bmi_rx_port = priv->rx_port;
    dma_addr_t buf;
    int i, j;
    int mac_idx = priv->num;
    u16 val;

    /* Alloc global parameter ram at MURAM */
    if (priv->tx_pram) {
        priv->rx_pram = priv->tx_pram;
        pram = priv->tx_pram;
    } else   {
        if (fman_is_active(priv->reg, mac_idx)) {
            printk("%s: Could not allocate muram when other BMI ports are active.\n",
                   __func__);
            return 0;
        }
        pram = (struct fm_port_global_pram *)fm_muram_alloc(priv->fm_index, FM_PRAM_SIZE, FM_PRAM_ALIGN);
        priv->rx_pram = pram;
    }

    /* Parameter page offset to MURAM */
    pram_page_offset = (u64)pram - (u64)fm_muram_base(priv->fm_index);

    TRACE("Rx param address (virt): 0x%llx, (phy): 0x%x\n",(u64)pram, pram_page_offset + 0x1a00000);

    /* Enable global mode- snooping data buffers and BDs */
    TRACE("rx_port_pram mode: 0x%llx\n", (u64)&pram->mode - (u64)pram);
    fm_im_write(&pram->mode, PRAM_MODE_GLOBAL);

    /* Init the Rx queue descriptor pionter */
    TRACE("rx_port_pram rxqd_ptr: 0x%llx\n", (u64)&pram->rxqd_ptr - (u64)pram);
    fm_im_write(&pram->rxqd_ptr, pram_page_offset + 0x20);

    /* Set the max receive buffer length, power of 2 */
    TRACE("rx_port_pram mrblr: 0x%llx\n", (u64)&pram->mrblr - (u64)pram);
    muram_writew(&pram->mrblr, MAX_RXBUF_LOG2);

    /* Alloc Rx buffer descriptors from main memory */
    rx_bd_ring_base = kzalloc(sizeof(struct fm_port_bd) * RX_BD_RING_SIZE, GFP_KERNEL);
    if (!rx_bd_ring_base)
        return 0;
    memset(rx_bd_ring_base, 0, sizeof(struct fm_port_bd) * RX_BD_RING_SIZE);

    /* Alloc Rx buffer from main memory */
    priv->rx_skbuff = kmalloc(sizeof(*priv->rx_skbuff) * RX_BD_RING_SIZE, GFP_KERNEL);
    if (!priv->rx_skbuff) {
        printk("Could not allocate rx_skbuff\n");
        return 0;
    }

    for (j = 0; j < RX_BD_RING_SIZE; j++)
        priv->rx_skbuff[j] = NULL;

    /* Save them to priv */
    priv->rx_bd_ring = rx_bd_ring_base;
    priv->cur_rxbd = rx_bd_ring_base;
    priv->skb_currx = 0;

    /* Init Rx BDs ring */
    rxbd = (struct fm_port_bd *)rx_bd_ring_base;
    for (i = 0; i < RX_BD_RING_SIZE; i++) {
        struct sk_buff *skb;
        skb = netdev_alloc_skb(priv->ndev, priv->rx_buffer_size + RXBUF_ALIGNMENT);
        if (!skb) {
            printk("Can't allocate RX buffers\n");
            return 0;
        }
        skb_reserve(skb, RXBUF_ALIGNMENT - (((unsigned long) skb->data) & (RXBUF_ALIGNMENT - 1)));
        priv->rx_skbuff[i] = skb;
    
        buf = dma_map_single(priv->dev, skb->data, priv->rx_buffer_size, DMA_FROM_DEVICE);
        TRACE("------rxbd buf addr: 0x%0llx------\n", buf);
    
        muram_writew(&rxbd->status, RxBD_EMPTY);
        muram_writew(&rxbd->len, 0);
        muram_writew(&rxbd->buf_ptr_hi, (buf >> 32) & 0xffff);
        fm_im_write(&rxbd->buf_ptr_lo, (u32)(buf & 0xffffffff));
        rxbd++;
    }

    /* Set the Rx queue descriptor */
    TRACE("rx_port_pram rxqd: 0x%llx\n", (u64)&pram->rxqd - (u64)pram);
    rxqd = &pram->rxqd;
    muram_writew(&rxqd->gen, RX_QD_RXF_INTMASK | RX_QD_BSY_INTMASK | priv->fpm_event_num);
    val = muram_readw(&rxqd->gen);
    buf = virt_to_phys(rx_bd_ring_base);
    TRACE("------rxqd bdring phys addr: 0x%0llx, virtual addr %p ------\n", buf, rx_bd_ring_base);
    muram_writew(&rxqd->bd_ring_base_hi, (buf >> 32) & 0xffff);
    fm_im_write(&rxqd->bd_ring_base_lo, (u32)(buf & 0xffffffff));
    muram_writew(&rxqd->bd_ring_size, sizeof(struct fm_port_bd) * RX_BD_RING_SIZE);
    muram_writew(&rxqd->offset_in, 0);
    muram_writew(&rxqd->offset_out, 0);

    /* Set IM parameter ram pointer to Rx Frame Queue ID */
    fm_im_write(&bmi_rx_port->fmbm_rfqid, pram_page_offset);

    return 1;
}

static int fm_eth_tx_port_parameter_init(struct fm_im_private *priv)
{
    struct fm_port_global_pram *pram;
    u32 pram_page_offset;
    void *tx_bd_ring_base;
    struct fm_port_bd *txbd;
    struct fm_port_qd *txqd;
    struct fm_bmi_tx_port *bmi_tx_port = priv->tx_port;
    dma_addr_t buf;
    int i;
    int mac_idx = priv->num;

    /* Alloc global parameter ram at MURAM */
    if (priv->rx_pram) {
        priv->tx_pram = priv->rx_pram;
        pram = priv->rx_pram;
    } else {
        if (fman_is_active(priv->reg, mac_idx)) {
            printk("%s: Could not allocate muram when other BMI ports are active.\n",
                   __func__);
            return 0;
        }
        pram = (struct fm_port_global_pram *)fm_muram_alloc(priv->fm_index,
                FM_PRAM_SIZE, FM_PRAM_ALIGN);
        priv->tx_pram = pram;
    }

    /* Parameter page offset to MURAM */
    pram_page_offset = (u64)pram - (u64)fm_muram_base(priv->fm_index);

    TRACE("Rx param address (virt): 0x%llx, (phy): 0x%x\n", (u64)pram, pram_page_offset + 0x1a00000);

    /* Enable global mode- snooping data buffers and BDs */
    TRACE("tx_port_pram mode: 0x%llx\n", (u64)&pram->mode - (u64)pram);
    fm_im_write(&pram->mode, PRAM_MODE_GLOBAL);

    /* Init the Tx queue descriptor pionter */
    TRACE("tx_port_pram txqd_ptr: 0x%llx\n", (u64)&pram->txqd_ptr - (u64)pram);
    fm_im_write(&pram->txqd_ptr, pram_page_offset + 0x40);

    /* Alloc Tx buffer descriptors from main memory */
    tx_bd_ring_base = kzalloc(sizeof(struct fm_port_bd) * TX_BD_RING_SIZE, GFP_KERNEL);
    if (!tx_bd_ring_base)
        return 0;
    memset(tx_bd_ring_base, 0, sizeof(struct fm_port_bd) * TX_BD_RING_SIZE);
    /* Save it to priv */
    priv->tx_bd_ring = tx_bd_ring_base;
    priv->cur_txbd = tx_bd_ring_base;
    priv->skb_curtx = 0;

    /* Init Tx BDs ring */
    txbd = (struct fm_port_bd *)tx_bd_ring_base;
    for (i = 0; i < TX_BD_RING_SIZE; i++) {
        muram_writew(&txbd->status, TxBD_LAST);
        muram_writew(&txbd->len, 0);
        muram_writew(&txbd->buf_ptr_hi, 0);
        fm_im_write(&txbd->buf_ptr_lo, 0);
        txbd++;
    }

    /* Alloc SKB free queue from main memory */
    priv->tx_skbuff = kmalloc(sizeof(*priv->tx_skbuff) * TX_BD_RING_SIZE, GFP_KERNEL);
    if (!priv->tx_skbuff) {
        printk("Could not allocate tx_skbuff\n");
        return 0;
    }

    for (i = 0; i < TX_BD_RING_SIZE; i++)
        priv->tx_skbuff[i] = NULL;

    /* Set the Tx queue decriptor */
    TRACE("tx_port_pram txqd: 0x%llx\n", (u64)&pram->txqd - (u64)pram);
    txqd = &pram->txqd;
    buf = virt_to_phys(tx_bd_ring_base);
    TRACE("------txqd bdring phys addr: 0x%0llx, virtual addr %p ------\n", buf, tx_bd_ring_base);
    muram_writew(&txqd->bd_ring_base_hi, (buf >> 32) & 0xffff);
    fm_im_write(&txqd->bd_ring_base_lo, (u32)(buf & 0xffffffff));
    muram_writew(&txqd->bd_ring_size, sizeof(struct fm_port_bd) * TX_BD_RING_SIZE);
    muram_writew(&txqd->offset_in, 0);
    muram_writew(&txqd->offset_out, 0);

    /* Set IM parameter ram pointer to Tx Confirmation Frame Queue ID */
    fm_im_write(&bmi_tx_port->fmbm_tcfqid, pram_page_offset);

    return 1;
}


static int port_parameter_init(struct fm_im_private *priv)
{

    if (!fm_eth_rx_port_parameter_init(priv))
        return 0;

    if (!fm_eth_tx_port_parameter_init(priv))
        return 0;

    return 1;
}

static void memac_init_mac(struct fsl_enet_mac *mac)
{
    struct memac *regs = mac->base;

    /* Mask all interrupt */
    fm_im_write(&regs->imask, IMASK_MASK_ALL);

    /* Clear all events */
    fm_im_write(&regs->ievent, IEVENT_CLEAR_ALL);

    /* Set the max receive length */
    fm_im_write(&regs->maxfrm, mac->max_rx_len & MAXFRM_MASK);

    /* Multicast frame reception for the hash entry disable */
    fm_im_write(&regs->hashtable_ctrl, 0);
}

static void memac_enable_mac(struct fsl_enet_mac *mac)
{
    struct memac *regs = mac->base;

    fm_im_setbits(&regs->command_config, MEMAC_CMD_CFG_RXTX_EN | MEMAC_CMD_CFG_NO_LEN_CHK); 
}

static void memac_disable_mac(struct fsl_enet_mac *mac)
{
    struct memac *regs = mac->base;

    fm_im_clrbits(&regs->command_config, MEMAC_CMD_CFG_RXTX_EN);
}

static void memac_set_mac_addr(struct fsl_enet_mac *mac, u8 *mac_addr)
{
    struct memac *regs = mac->base;
    u32 mac_addr0, mac_addr1;
    u32 val0, val1;

    /*
     * If a station address of 0x12345678ABCD, perform a write to
     * MAC_ADDR0 of 0x78563412, MAC_ADDR1 of 0x0000CDAB
     */
    mac_addr0 = (mac_addr[3] << 24) | (mac_addr[2] << 16) | \
                    (mac_addr[1] << 8)  | (mac_addr[0]);
    fm_im_write(&regs->mac_addr_0, mac_addr0);

    mac_addr1 = ((mac_addr[5] << 8) | mac_addr[4]) & 0x0000ffff;
    fm_im_write(&regs->mac_addr_1, mac_addr1);
    val0 = fm_im_read(&regs->mac_addr_0);
    val1 = fm_im_read(&regs->mac_addr_1);
    TRACE("%s: mac_addr0 = 0x%0x, mac_addr0 = 0x%0x\n", __func__, val0, val1);
}

static void memac_set_interface_mode(struct fsl_enet_mac *mac, phy_interface_t type, int speed)
{
    struct memac *regs = mac->base;
    u32 if_mode, if_status;

    /* Clear all bits relative with interface mode */
    if_mode = fm_im_read(&regs->if_mode);
    if_status = fm_im_read(&regs->if_status);

    /* Set interface mode */
    switch (type) {
    case PHY_INTERFACE_MODE_GMII:
        if_mode &= ~IF_MODE_MASK;
        if_mode |= IF_MODE_GMII;
        break;
    case PHY_INTERFACE_MODE_RGMII:
        if_mode |= (IF_MODE_GMII | IF_MODE_RG);
        break;
    case PHY_INTERFACE_MODE_RGMII_TXID:
	if_mode |= (IF_MODE_GMII | IF_MODE_RG);
	break; 
    case PHY_INTERFACE_MODE_RMII:
        if_mode |= (IF_MODE_GMII | IF_MODE_RM);
        break;
    case PHY_INTERFACE_MODE_SGMII:
        if_mode &= ~IF_MODE_MASK;
        if_mode |= (IF_MODE_GMII);
        break;
    case PHY_INTERFACE_MODE_XGMII:
        if_mode &= ~IF_MODE_MASK;
        if_mode |= IF_MODE_XGMII;
        break;
    default:
        break;
    }
    /* Enable automatic speed selection for Non-XGMII */
    if (type != PHY_INTERFACE_MODE_XGMII)
        if_mode |= IF_MODE_EN_AUTO;

    if ((type == PHY_INTERFACE_MODE_RGMII) ||
        (type == PHY_INTERFACE_MODE_RGMII_TXID)) {
        if_mode &= ~IF_MODE_EN_AUTO;
        if_mode &= ~IF_MODE_SETSP_MASK;
        switch (speed) {
        case SPEED_1000:
            if_mode |= IF_MODE_SETSP_1000M;
            break;
        case SPEED_100:
            if_mode |= IF_MODE_SETSP_100M;
            break;
        case SPEED_10:
            if_mode |= IF_MODE_SETSP_10M;
        default:
            break;
        }
    }

    TRACE(" %s: if_mode = 0x%0x\n", __func__, if_mode);
    TRACE(" %s: if_status = 0x%0x\n", __func__, if_status);
    fm_im_write(&regs->if_mode, if_mode);

    return;
}

void init_memac(struct fsl_enet_mac *mac, void *base, void *phyregs, int max_rx_len)
{
    mac->base = base;
    mac->phyregs = phyregs;
    mac->max_rx_len = max_rx_len;
    mac->init_mac = memac_init_mac;
    mac->enable_mac = memac_enable_mac;
    mac->disable_mac = memac_disable_mac;
    mac->set_mac_addr = memac_set_mac_addr;
    mac->set_if_mode = memac_set_interface_mode;
}

static int fm_eth_init_mac(struct fm_im_private *priv, struct ccsr_fman *reg)
{
    struct fsl_enet_mac *mac;
    void *base, *phyregs = NULL;
    int num;

    num = priv->num;

    if (priv->type == FM_ETH_10G_E)
        num += 8;
    base = &reg->memac[num].fm_memac;
    phyregs = &reg->memac[num].fm_memac_mdio;
    TRACE("%s(): memac mdio base (virt):0x%llx\n", __func__, (u64)phyregs);

    /* Alloc mac controller */
    mac = kzalloc(sizeof(struct fsl_enet_mac), GFP_KERNEL);
    if (!mac)
        return 0;
    memset(mac, 0, sizeof(struct fsl_enet_mac));

    /* Save the mac to fm_eth struct */
    priv->mac = mac;

    init_memac(mac, base, phyregs, MAX_RXBUF_LEN);

    return 1;
}

static void adjust_link(struct net_device *dev) 
{
    struct fm_im_private *priv = netdev_priv(dev);
    struct memac __iomem *regs = priv->mac->base;
    struct phy_device *phydev = priv->phydev;
    uint32_t tmp;
    int new_state = 0;
    u32 if_mode, if_status;
	
	
//	if (priv->ecdev) {
//		ecdev_set_link(priv->ecdev, priv->oldlink ? 1 : 0);
//		return;
//	}

    if (phydev->link) {
        tmp = fm_im_read(&regs->if_mode);

        if (phydev->duplex != priv->oldduplex) {
            new_state = 1;
            if (phydev->duplex)
                tmp &= ~IF_MODE_HD;
            else
                tmp |= IF_MODE_HD;

            priv->oldduplex = phydev->duplex;
        }

        if ((phydev->speed != priv->oldspeed) &&
            ((priv->interface == PHY_INTERFACE_MODE_RGMII) ||
            (priv->interface == PHY_INTERFACE_MODE_RGMII_TXID))) {
            new_state = 1;

            /* Configure RGMII in manual mode */
            tmp &= ~IF_MODE_EN_AUTO;
            tmp &= ~IF_MODE_SETSP_MASK;

            if (phydev->duplex)
                tmp |= IF_MODE_RGMII_FD;
            else
                tmp &= ~IF_MODE_RGMII_FD;

            switch (phydev->speed) {
                case 1000:
                    tmp |= IF_MODE_SETSP_1000M;
                    break;
                case 100:
                    tmp |= IF_MODE_SETSP_100M;
                    break;
                case 10:
                    tmp |= IF_MODE_SETSP_10M;
                    break;
                default:
                    break;
            }
            priv->oldspeed = phydev->speed;
        }
        fm_im_write(&regs->if_mode, tmp);

        if (!priv->oldlink) {
            new_state = 1;
            priv->oldlink = 1;
        }
    } else if (priv->oldlink) {
        new_state = 1;
        priv->oldlink = 0;
        priv->oldspeed = 0;
        priv->oldduplex = -1;
    }

    if (new_state && netif_msg_link(priv))
        phy_print_status(phydev);

    if_mode = fm_im_read(&regs->if_mode);
    if_status = fm_im_read(&regs->if_status);
    TRACE("%s(): if_mode:0x%0x, if_status:0x%0x\n", __func__, if_mode, if_status);
}

static int init_phy(struct net_device *dev)
{
    struct fm_im_private* priv = netdev_priv(dev);
    u32 supported;

    priv->oldlink = 0;
    priv->oldspeed = 0;
    priv->oldduplex = -1;

    priv->phydev = of_phy_connect(dev, priv->phy_node, &adjust_link, 0, priv->interface);

    if (!priv->phydev) {
        dev_err(&dev->dev, "could not attach to PHY\n");
        return -ENODEV;
    }

    if (priv->type == FM_ETH_1G_E) {
        supported = (SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full |
                        SUPPORTED_100baseT_Half | SUPPORTED_100baseT_Full |
                        SUPPORTED_1000baseT_Full);
    } else {
        supported = SUPPORTED_10000baseT_Full;
    }

    /* Remove any features not supported by the controller */
    priv->phydev->supported &= supported;
    priv->phydev->advertising = priv->phydev->supported;

    return 0;
}

static void fm_init_qmi(struct ccsr_fman *reg, int mac_idx)
{
    struct fm_qmi_common *qmi = &(reg->fm_qmi_common);

    /* Disable enqueue and dequeue of QMI */
    fm_im_clrbits(&qmi->fmqm_gc, FMQM_GC_ENQ_EN | FMQM_GC_DEQ_EN);

    if (!fman_is_active(reg, mac_idx)) {
        /* Disable all error interrupts */
        fm_im_write(&qmi->fmqm_eien, FMQM_EIEN_DISABLE_ALL);
        /* Clear all error events */
        fm_im_write(&qmi->fmqm_eie, FMQM_EIE_CLEAR_ALL);
    
        /* Disable all interrupts */
        fm_im_write(&qmi->fmqm_ien, FMQM_IEN_DISABLE_ALL);
        /* Clear all interrupts */
        fm_im_write(&qmi->fmqm_ie, FMQM_IE_CLEAR_ALL);
    }
}

static void fm_init_fpm(struct ccsr_fman *reg, int mac_idx)
{
    int i;
    struct fm_fpm *fpm = &(reg->fm_fpm);

    if (!fman_is_active(reg, mac_idx)) {
        /* Disable the dispatch limit in IM case */
        fm_im_write(&fpm->fpmflc, FMFP_FLC_DISP_LIM_NONE);
        /* Clear events */
        fm_im_write(&fpm->fmfpee, FMFPEE_CLEAR_EVENT);
    
        /* Clear risc events */
        for (i = 0; i < 4; i++)
            fm_im_write(&fpm->fpmcev[i], 0xffffffff);
    
        /* Clear error */
        fm_im_write(&fpm->fpmrcr, FMFP_RCR_MDEC | FMFP_RCR_IDEC);
    }
}

static int fm_init_bmi(int fm_idx, int mac_idx, struct ccsr_fman *reg)
{
    int blk;
    u32 val, offset;
    void *base;
    struct fm_bmi_common *bmi = &(reg->fm_bmi_common);

    /* Assume U-Boot or other FMAN software has changed it.*/
    if ((!fman_is_active(reg, mac_idx))) {
        /* Disable all BMI interrupt */
        fm_im_write(&bmi->fmbm_ier, FMBM_IER_DISABLE_ALL);
    
        /* Clear all events */
        fm_im_write(&bmi->fmbm_ievr, FMBM_IEVR_CLEAR_ALL);
    
        /* Alloc free buffer pool in MURAM */
        base = fm_muram_alloc(fm_idx, FM_FREE_POOL_SIZE, FM_FREE_POOL_ALIGN);
        if (!base) {
            printk("%s: no muram for free buffer pool\n", __func__);
            return -ENOMEM;
        }
        offset = base - fm_muram_base(fm_idx);
    
        /* Need 128KB total free buffer pool size */
        val = offset / 256;
        blk = FM_FREE_POOL_SIZE / 256;

        /* In IM, we must not begin from offset 0 in MURAM */
        val |= ((blk - 1) << FMBM_CFG1_FBPS_SHIFT);
        fm_im_write(&bmi->fmbm_cfg1, val);
        fm_im_write(&bmi->fmbm_cfg2, FMBM_CFG2_TNTSKS_MASK);
    
        /* Initialize internal buffers data base (linked list) */
        fm_im_write(&bmi->fmbm_init, FMBM_INIT_START);
    }
    return 0;
}

static int fm_init_common(int fm_idx, int mac_idx, struct ccsr_fman *reg)
{
    /* Workaround: to de-active all the ports first */
    fman_de_active(reg);
    fm_init_muram(fm_idx, &reg->muram);
    fm_init_qmi(reg, mac_idx);
    fm_init_fpm(reg, mac_idx);

    if (!fman_is_active(reg, mac_idx)) {
        /* Clear DMA status */
        fm_im_setbits(&reg->fm_dma.fmdmsr, FMDMSR_CLEAR_ALL);

        /* Set DMA mode */
        fm_im_setbits(&reg->fm_dma.fmdmmr, FMDMMR_SBER);
    }

    return fm_init_bmi(fm_idx, mac_idx, reg);
}

int check_shared_interrupt(struct fm_im_private *priv, u32 pending)
{
    if((pending & FMNPI_EN_REV0) && priv->fpm_event_num == 0)
        return 1;
    if((pending & FMNPI_EN_REV1) && priv->fpm_event_num == 1)
        return 1;
    if((pending & FMNPI_EN_REV2) && priv->fpm_event_num == 2)
        return 1;
    if((pending & FMNPI_EN_REV3) && priv->fpm_event_num == 3)
        return 1;
    
    return 0;
}

static struct of_device_id fman_match[] =
{
    {
        .compatible = "fsl,im-ethercat",
    },
    {},
};
MODULE_DEVICE_TABLE(of, fman_match);

irqreturn_t fm_im_receive(int irq, void *private)
{
    struct fm_im_private *priv;
    struct net_device *dev;
    struct sk_buff *skb;
    struct fm_port_global_pram *pram;
    struct fm_port_bd *rxbd, *rxbd_base;
    u16 status, offset_out;
    u32 ievent, pending;
    int pkt_len;
    struct fm_fpm *fpm;
    dma_addr_t buf;
    u32 buf_lo, buf_hi;

    priv = (struct fm_im_private*)private;
    dev = priv->ndev;
    pram = priv->rx_pram;
    rxbd = priv->cur_rxbd;
    status = muram_readw(&rxbd->status);
    fpm = &priv->reg->fm_fpm;

    pending = fm_im_read(&fpm->fmnpi);
	if (!priv->ecdev) {
    	if(!check_shared_interrupt(priv, pending))
        	return IRQ_NONE;

    	/* Clear event register */
    	ievent = fm_im_read(&fpm->fpmfcevent[priv->fpm_event_num]);
    	fm_im_write(&fpm->fpmcev[priv->fpm_event_num], ievent);
	}

    while(!(status & RxBD_EMPTY)) {
        buf_hi = muram_readw(&rxbd->buf_ptr_hi);
        buf_lo = fm_im_read(&rxbd->buf_ptr_lo);
        buf = ((u64)buf_hi << 32) | buf_lo;

        dma_unmap_single(priv->dev, buf, priv->rx_buffer_size + RXBUF_ALIGNMENT,
                         DMA_FROM_DEVICE);
        skb = priv->rx_skbuff[priv->skb_currx];

        if (!skb || (!(status & (RxBD_FIRST | RxBD_LAST))) || (status & RxBD_ERROR)) {
            if (status & RxBD_ERROR)
                dev->stats.rx_errors++;
            else
                dev->stats.rx_dropped++;
			if (!priv->ecdev) {
            	dev_kfree_skb(skb);
			}
            priv->rx_skbuff[priv->skb_currx] = NULL;
         } else {
            pkt_len = muram_readw(&rxbd->len) - ETH_FCS_LEN;
			if (priv->ecdev) {
			    ecdev_receive(priv->ecdev, priv->rx_skbuff[priv->skb_currx], pkt_len);
			    // No need to detect link status as
			    // long as frames are received: Reset watchdog.
			    priv->ec_watchdog_jiffies = jiffies;
			}
			else
			{
            	skb_put(skb, pkt_len);
            	skb->protocol = eth_type_trans(skb, dev);
            	skb->dev = dev;
            	netif_rx(skb);			
			}
            dev->stats.rx_packets ++;
            dev->stats.rx_bytes += pkt_len;
         }

        /* Clear the RxBDs */
        muram_writew(&rxbd->status, RxBD_EMPTY);
        muram_writew(&rxbd->len, 0);
        mb();

        skb = netdev_alloc_skb(priv->ndev, priv->rx_buffer_size + RXBUF_ALIGNMENT);
        if (!skb) {
            if (printk_ratelimit())
                printk("Can't allocate Rx buffer\n");
            dev->stats.rx_dropped++;
            break;
        }
        skb_reserve(skb, RXBUF_ALIGNMENT -
                    (((unsigned long)skb->data) & (RXBUF_ALIGNMENT - 1)));
        buf = dma_map_single(priv->dev, skb->data,
                             priv->rx_buffer_size + RXBUF_ALIGNMENT, DMA_FROM_DEVICE);
        if (dma_mapping_error(priv->dev, buf)) {
            printk("%s: %d: dma_map_single error\n", __func__, __LINE__);
            break;
        }
        priv->rx_skbuff[priv->skb_currx] = skb;
        muram_writew(&rxbd->buf_ptr_hi, (buf >> 32) & 0xffff);
        fm_im_write(&rxbd->buf_ptr_lo, (u32)(buf & 0xffffffff));
        mb();

        /* Advance RxBD */
        rxbd++;
        rxbd_base = (struct fm_port_bd *)priv->rx_bd_ring;
        if (rxbd >= (rxbd_base + RX_BD_RING_SIZE))
            rxbd = rxbd_base;
        /* Read next status */
        status = muram_readw(&rxbd->status);

        /* Update to point at the next skb */
        priv->skb_currx = (priv->skb_currx + 1) & (RX_BD_RING_SIZE - 1);

        /* Update RxQD */
        offset_out = muram_readw(&pram->rxqd.offset_out);
        offset_out += sizeof(struct fm_port_bd);
        if (offset_out >= muram_readw(&pram->rxqd.bd_ring_size))
            offset_out = 0;
        muram_writew(&pram->rxqd.offset_out, offset_out);
        mb();

    }
    priv->cur_rxbd = (void *)rxbd;

    return IRQ_HANDLED;
}


static void ec_poll(struct net_device *dev)
{
	struct fm_im_private *tp = netdev_priv(dev);
	
	
	fm_im_receive(IRQF_SHARED|IRQF_NO_SUSPEND, tp); // FIXME
//		rtl_tx(dev, tp);
    
	if (jiffies - tp->ec_watchdog_jiffies >= 2 * HZ) {
		ecdev_set_link(tp->ecdev, tp->oldlink ? 1 : 0);
		tp->ec_watchdog_jiffies = jiffies;
	}
}
static int fm_im_startup(struct net_device *dev)
{
    struct fm_im_private *priv;
    struct memac *regs;

    priv = netdev_priv(dev);

    /* Rx/TxBDs, Rx/TxQDs, Rx buff and parameter ram init */
    if(!port_parameter_init(priv))
        return 0;

    regs = priv->mac->base;
    TRACE("%s(): memac%d controller base:0x%llx\n", __func__, priv->num, (u64)regs);

    priv->mac->init_mac(priv->mac);

    return 1;
}

static int fm_im_enet_open(struct net_device *dev)
{
    struct fm_im_private *priv;
    struct fsl_enet_mac *mac;
    int i, err;
    u32 val;
    
    priv = netdev_priv(dev);
	if (!priv->ecdev) {
    err = request_irq(priv->irq, fm_im_receive, IRQF_SHARED|IRQF_NO_SUSPEND, "fman_im", priv);
    if (err < 0)
        printk("Request irq ERROR!\n");
	}
    mac = priv->mac;
    mac->set_mac_addr(mac, dev->dev_addr);

    if(init_phy(dev))
        return 0;

    /* Init bmi rx port, IM mode and disable */
    bmi_rx_port_init(priv, priv->rx_port);
    /* Enable bmi Rx port */
    fm_im_write(&priv->rx_port->fmbm_rfqid, ((u64)priv->rx_pram - (u64)fm_muram_base(priv->fm_index)));
    fm_im_setbits(&priv->rx_port->fmbm_rcfg, FMBM_RCFG_EN);

    /* Enable MAC rx/tx port */
    mac->enable_mac(mac);

    /* Init bmi tx port, IM mode and disable */
    bmi_tx_port_init(priv, priv->tx_port);
    /* Enable bmi Tx port */
    fm_im_write(&priv->tx_port->fmbm_tcfqid,((u64)priv->tx_pram - (u64)fm_muram_base(priv->fm_index)));
    fm_im_setbits(&priv->tx_port->fmbm_tcfg, FMBM_TCFG_EN);
    /* Re-enable transmission of frame */
    fm_im_clrbits(&priv->tx_pram->mode, PRAM_MODE_GRACEFUL_STOP);
    /* Enable interrupt */
    for(i = 0; i < 4; i++) {
        fm_im_setbits(&(&priv->reg->fm_fpm)->fpmfcmask[i], FMFPCEE_IM_MASK_RXF);
        val = fm_im_read(&(&priv->reg->fm_fpm)->fpmfcmask[i]);
        TRACE("%s():%d: fpmfcmask[%d] = 0x%x\n", __func__, __LINE__, i, val);
    }

    mb();

    phy_start(priv->phydev);

    /* Set the MAC-PHY mode */
    mac->set_if_mode(mac, priv->interface, priv->phydev->speed);
	if (!priv->ecdev) {
    	netif_start_queue(dev);
	}

    for(i = 0; i < 4; i++) {
        val = fm_im_read(&(&priv->reg->fm_fpm)->fpmfcevent[i]);
        TRACE("%s(): fpmfcevent[%d] = 0x%x\n", __func__, i, val);
    }
    return 0;
}

static int fm_im_close(struct net_device *dev)
{

    struct fm_im_private *priv = netdev_priv(dev);
    struct fm_port_global_pram *tx_pram = priv->tx_pram;
    int i;

    /* Allow the Fman (Tx) port to process in-flight frames before we
     * try switching it off.
     */
    /* Re-enable transmission of frame */
    fm_im_setbits(&tx_pram->mode, PRAM_MODE_GRACEFUL_STOP); 
    usleep_range(5000, 10000);

    phy_stop(priv->phydev);

    for(i = 0; i < 4; i++) 
        fm_im_setbits(&(&priv->reg->fm_fpm)->fpmfcmask[i], 0x0);
    
    /* Clear DMA status */
    fm_im_setbits(&priv->reg->fm_dma.fmdmsr, FMDMSR_CLEAR_ALL);

    /* Disable bmi Tx port */
    fm_im_clrbits(&priv->tx_port->fmbm_tcfg, FMBM_TCFG_EN);

    /* Disable MAC rx/tx port */
    priv->mac->disable_mac(priv->mac);

    /* Disable bmi Rx port */
    fm_im_clrbits(&priv->rx_port->fmbm_rcfg, FMBM_RCFG_EN);
	if (!priv->ecdev) {
 	   /* Release irq line */
    	free_irq(priv->irq, priv);
	}
    /* Free skb resource */
    /* Not implemented yet */

    /* Disconnect from the PHY */
    phy_disconnect(priv->phydev);
    priv->phydev = NULL;
	if (!priv->ecdev) {
    	netif_stop_queue(dev);
	}
    return 0;
}

static int fm_im_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct fm_im_private *priv;
    struct fm_port_global_pram *pram;
    struct fm_port_bd *txbd, *txbd_base;
    u16 offset_in;
    dma_addr_t buf;
    int i;

    priv = netdev_priv(dev);
    pram = priv->tx_pram;
    txbd = priv->cur_txbd;

#ifdef DEBUG
    fm_im_xmit_dump(skb);
#endif

    i = priv->skb_curtx;

    if (!priv->ecdev && (priv->tx_skbuff[i]))
        dev_kfree_skb(priv->tx_skbuff[i]);
    /* Save the skb pointer so we can free it later */
    priv->tx_skbuff[i] = skb;
    /* Move forward and wrap if come to end */
    priv->skb_curtx = (priv->skb_curtx + 1) & (TX_BD_RING_SIZE - 1);

    /* Setup TxBD */
    buf = dma_map_single(priv->dev, skb->data, skb->len, DMA_TO_DEVICE);
    if (dma_mapping_error(priv->dev, buf)) {
        printk("%s: %d: dma_map_single error\n", __func__, __LINE__);
        dev->stats.tx_dropped ++;
        return NETDEV_TX_BUSY;
    }
    TRACE("------Tx buffer addr: 0x%0llx------\n", buf);
    muram_writew(&txbd->buf_ptr_hi, (buf >> 32) & 0xffff);
    fm_im_write(&txbd->buf_ptr_lo, (u32)(buf & 0xffffffff));
    muram_writew(&txbd->len, skb->len);
    mb();
    muram_writew(&txbd->status, TxBD_READY | TxBD_LAST);
    mb();

    /* Update TxQD, let RISC to send the packet */
    offset_in = muram_readw(&pram->txqd.offset_in);
    offset_in += sizeof(struct fm_port_bd);
    if (offset_in >= muram_readw(&pram->txqd.bd_ring_size))
            offset_in = 0;
    muram_writew(&pram->txqd.offset_in, offset_in);
    mb();

   /* Wait for buffer to be transmitted */
    for (i = 0; muram_readw(&txbd->status) & TxBD_READY; i++) {
        udelay(100);
        if (i > 0x10000) {
            printk("%s: Tx error\n", dev->name);
            dev->stats.tx_dropped ++;
            return NETDEV_TX_BUSY;
        }
    }

    dev->stats.tx_bytes = txbd->len;
    dev->stats.tx_packets ++;
    /* Advance the TxBD */
    txbd++;
    txbd_base = (struct fm_port_bd *)priv->tx_bd_ring;
    if (txbd >= (txbd_base + TX_BD_RING_SIZE))
            txbd = txbd_base;
    /* Update current txbd */
    priv->cur_txbd = (void *)txbd;

    dma_unmap_single(priv->dev, buf, skb->len, DMA_TO_DEVICE);

    return NETDEV_TX_OK;
}

static int fm_im_change_mtu(struct net_device *dev, int new_mtu)
{
    int frame_size = new_mtu + ETH_HLEN;

    if ((frame_size < 64) || (frame_size > JUMBO_FRAME_SIZE)) {
        printk("%s(): invalid MTU setting\n", __func__);
        return -EINVAL;
    }
    
    dev->mtu = new_mtu;

    return 0;
}

/* Change the promiscuity of the device based on the flags
 * (this function is called whenever dev->flags is changed)
 */
static void fm_im_set_rx_mode(struct net_device *dev)
{
    struct fm_im_private *priv = netdev_priv(dev);
    struct memac *regs = priv->mac->base;

    if (dev->flags & IFF_PROMISC) {
        /* Set CONFIG_COMMAND to PROM */
        fm_im_setbits(&regs->command_config, MEMAC_CMD_CFG_PROMIS);
    } else {
        /* Set CONFIG_COMMAND to non PROM */
        fm_im_clrbits(&regs->command_config, MEMAC_CMD_CFG_PROMIS);
    }
}

static void fm_im_timeout(struct net_device *dev)
{
    dev->stats.tx_errors++;
    /* ToDo: re-schedule to work
     * schedule_work(&priv->reset_task);
     */
}

static int fm_im_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
    return 0;
}

static int fm_im_set_mac_addr(struct net_device *dev, void *p)
{
    struct fm_im_private *priv = netdev_priv(dev);
    struct fsl_enet_mac *mac;

    eth_mac_addr(dev, p);

    mac = priv->mac;
    mac->set_mac_addr(mac, p);

    return 0;
}

static const struct net_device_ops fm_im_netdev_ops = {
    .ndo_open = fm_im_enet_open,
    .ndo_start_xmit = fm_im_start_xmit,
    .ndo_stop = fm_im_close,
    .ndo_change_mtu = fm_im_change_mtu,
    .ndo_set_rx_mode = fm_im_set_rx_mode,
    .ndo_tx_timeout = fm_im_timeout,
    .ndo_do_ioctl = fm_im_ioctl,
    .ndo_set_mac_address = fm_im_set_mac_addr,
};

static phys_addr_t sys_ccsrbar, sys_fm1_offset;
static phys_addr_t sys_fm1_addr;

static int fm_im_remove(struct platform_device *of_dev)
{
    struct fm_im_private *priv = dev_get_drvdata(&of_dev->dev);
    int i;
    struct fm_port_bd *txbd,*rxbd;
    dma_addr_t buf;
    struct sk_buff *skb;
    
    if (priv->phy_node)
        of_node_put(priv->phy_node);
    if (priv->tbi_node)
        of_node_put(priv->tbi_node);

    dev_set_drvdata(&of_dev->dev, NULL);
    
    /* free Rx resources */
    for (i = 0, rxbd=priv->rx_bd_ring; i < RX_BD_RING_SIZE; i++) {
        skb = priv->rx_skbuff[i];
        buf = ((uint64_t)rxbd->buf_ptr_hi << 32) + rxbd->buf_ptr_lo;
        dma_unmap_single(priv->dev, buf, skb->len, DMA_FROM_DEVICE);
		if (!priv->ecdev) {
        	dev_kfree_skb(skb);
		}
        rxbd++;
    }
    kfree( priv->rx_bd_ring);
    kfree(priv->rx_skbuff);

    /* free Tx resources */
    for (i = 0, txbd=priv->tx_bd_ring; i < TX_BD_RING_SIZE; i++, txbd++) {
        if (!priv->tx_skbuff[i])
            continue;
        skb = priv->tx_skbuff[i];
        buf = ((uint64_t)txbd->buf_ptr_hi << 32) + txbd->buf_ptr_lo;
        dma_unmap_single(priv->dev, buf, skb->len, DMA_TO_DEVICE);
		if (!priv->ecdev) {
        	dev_kfree_skb(skb);
		}
    }
    kfree( priv->tx_bd_ring);
    kfree(priv->tx_skbuff);
    if (priv->ecdev) {
		ecdev_close(priv->ecdev);
		ecdev_withdraw(priv->ecdev);
	} else {    
    	unregister_netdev(priv->ndev);
	}
    free_netdev(priv->ndev);
    
    return 0;       
}

static int fm_im_probe(struct platform_device *of_dev) 
{
    struct ccsr_fman __iomem *reg;
    static struct ccsr_fman *fm1_reg = NULL;
    static int fm1_flag = 0;
    struct net_device *net_dev = NULL;
    struct fm_im_private *priv = NULL;
    struct device *dev = &of_dev->dev;
    const char *dev_name, *ctype;
    const int *fm_id, *mac_id, *fpm_event_id;
    int fm_idx, mac_idx;
    u16 rx_port_id, tx_port_id;
    const struct of_device_id *match;
    const void *mac_addr;
    struct device_node *mac_node;
    char *cp = NULL;
    int i = 0, err = 0;

    match = of_match_device(fman_match, dev);
    if (!match) {
        printk("%s(): No matching device found.\n", __func__);
        return -EINVAL;
    }

    if (dev->init_name)
        dev_name = dev->init_name;
    else
        dev_name = (&dev->kobj)->name;

    TRACE("--------------------------------------------\n"); 
    mac_node = of_parse_phandle(dev->of_node, "fsl,fman-mac", 0);
    if (!mac_node) {
        printk("%s(): of_parse_phandle get fsl,fman-mac failed!\n", __func__);
        return -EINVAL;
    }

    fm_id = of_get_property(mac_node->parent, "cell-index", NULL);
    if(!fm_id) {
        printk("of_get_property get cell-index failed!\n");
        return -EINVAL;
    }
    mac_id = of_get_property(mac_node, "cell-index", NULL);
    if(!mac_id) {
        printk("of_get_property get cell-index failed!\n");
        return -EINVAL;
    }

    fm_idx = fm_im_read((unsigned __iomem *)fm_id);
    mac_idx = fm_im_read((unsigned __iomem *)mac_id);
    /* In driver, index starts from 0, while in reference manual,
     * it starts from 1, align to RM.
     */
    printk("DEV: FM%d@DTSEC%d, DTS Node: %s\n", fm_idx+1, mac_idx+1, dev_name);

    fpm_event_id = of_get_property(dev->of_node, "fpmevt-sel", NULL);
    if(!fpm_event_id) {
        printk("of_get_property get fpmevt-sel failed!\n");
	return -EINVAL;
    }

    rx_port_id = RX_PORT_1G_BASE + mac_idx;
    tx_port_id = TX_PORT_1G_BASE + mac_idx;

    sys_ccsrbar = CONFIG_SYS_CCSRBAR_BASE;
    sys_fm1_offset = CONFIG_SYS_FM1_OFFSET;
    sys_fm1_addr = (sys_ccsrbar + sys_fm1_offset);

    if(fm_idx == 0) {
        if(!fm1_reg) {
            TRACE("FM1 FIRST DETECTED! IOREMAP......\n");
            reg = ioremap(sys_fm1_addr, sizeof(ccsr_fman_t));
            TRACE("FM1 phy base: 0x%x, virt base: 0x%llx, size: 0x%x\n",
                  (u32)sys_fm1_addr, (u64)reg, sizeof(ccsr_fman_t));
            fm_init_common(fm_idx, mac_idx, reg);
            fm1_reg = reg;
        } else {
            reg = fm1_reg;
            fm1_flag = 1;
        }
    } else {
        printk("FM NUM ERROR!\n");
        return -EINVAL;
    }

    net_dev = alloc_etherdev(sizeof(*priv));    
    if(!net_dev) {
        dev_err(dev, "alloc_etherdev() failed\n");
        err = -ENOMEM;
        goto alloc_etherdev_fail; 
    }

    priv = netdev_priv(net_dev);
    priv->ndev = net_dev;
    priv->ofdev = of_dev;
    priv->dev = dev;
    SET_NETDEV_DEV(net_dev, dev);  
    dev_set_drvdata(dev, priv);

    priv->reg = reg;
    priv->fm_index = fm_idx;
    priv->num = mac_idx;
    priv->type = FM_ETH_1G_E;
    priv->rx_buffer_size = DEFAULT_RX_BUFFER_SIZE;

    /* Enable most messages by default */
    priv->msg_enable = (NETIF_MSG_IFUP << 1 ) - 1;

    priv->rx_port = (void *)&reg->port[rx_port_id - 1].fm_bmi;
    priv->tx_port = (void *)&reg->port[tx_port_id - 1].fm_bmi;

    ctype = of_get_property(mac_node, "phy-connection-type", NULL);
    if(ctype && !strcmp(ctype, "rgmii-id"))
        priv->interface = PHY_INTERFACE_MODE_RGMII_ID;
    else if(ctype && !strcmp(ctype, "rgmii"))
        priv->interface = PHY_INTERFACE_MODE_RGMII;
    else if(ctype && !strcmp(ctype, "rgmii-txid"))
        priv->interface = PHY_INTERFACE_MODE_RGMII_TXID;
    else if(ctype && !strcmp(ctype, "sgmii"))
        priv->interface = PHY_INTERFACE_MODE_SGMII;
    else
        priv->interface = PHY_INTERFACE_MODE_MII;

    priv->phy_node = of_parse_phandle(mac_node, "phy-handle", 0);

    /* Find the TBI PHY.  If it's not there, we don't support SGMII */
    priv->tbi_node = of_parse_phandle(mac_node, "tbi-handle", 0);
    TRACE("ctype:%s, phy_node:%p, tbi_node:%p\n", ctype, priv->phy_node, priv->tbi_node);

    priv->irq = irq_of_parse_and_map(mac_node->parent, 0);
    TRACE("IRQ:%d\n", priv->irq);

    priv->fpm_event_num = fm_im_read((unsigned __iomem *)fpm_event_id);

    if(priv->fpm_event_num < 0 || priv->fpm_event_num > 3) {
        printk("of_get_property get wrong fpm event register num!\n");
        err = -EINVAL;
        goto ioremap_fail;
    }

    mac_addr = of_get_mac_address(mac_node);
    if (mac_addr) {
        memcpy(net_dev->dev_addr, mac_addr, ETH_ALEN);
        TRACE("MAC address: ");
        cp = (char *)mac_addr;
        for(i = 0; i < ETH_ALEN; i++) {
            TRACE("%02X", cp[i]);
            if(i != ETH_ALEN - 1)
                TRACE(":");
        }
        TRACE("\n");
    }

    /* Set the ethernet max receive length */
    priv->max_rx_len = MAX_RXBUF_LEN;

    /* Init global mac structure */
    if (!fm_eth_init_mac(priv, reg)) {
        err = -EINVAL;
        goto ioremap_fail;
    }

    /* To align the same name in U-Boot */
    sprintf(net_dev->name, "FM%d@DTSEC%d", fm_idx+1, mac_idx+1);

    if(!fm_im_startup(net_dev)) {
        err = -EINVAL;
        goto ioremap_fail;
    }
    net_dev->base_addr = (unsigned long)reg;
    net_dev->watchdog_timeo = HZ;
    net_dev->mtu = 1500;

    net_dev->netdev_ops = &fm_im_netdev_ops;

    spin_lock_init(&priv->lock);
	// offer device to EtherCAT master module
	priv->ecdev = ecdev_offer(net_dev, ec_poll, THIS_MODULE);
	priv->ec_watchdog_jiffies = jiffies;
	if (!priv->ecdev) {
    	err = register_netdev(net_dev);
    	if(err) {
        	printk("%s: register net device failed.\n", net_dev->name);
        	goto ioremap_fail;
    	}
	}
	
	if (priv->ecdev) {
		err = ecdev_open(priv->ecdev);
		if (err) {
			ecdev_withdraw(priv->ecdev);
		}
	}
    return 0;

ioremap_fail:
    iounmap(priv->reg);
alloc_etherdev_fail:
    free_netdev(priv->ndev);
    return err; 
}

static struct platform_driver fm_im_driver = {
    .driver = {
        .name           = KBUILD_MODNAME,
        .of_match_table = fman_match,
        .owner          = THIS_MODULE,
    },
    .probe	= fm_im_probe,
    .remove	= fm_im_remove,
};

static int __init __cold fm_im_load(void)
{
    int _errno;

    printk(KBUILD_MODNAME ": " "QorIQ FMAN Independent Mode Ethernet Driver\n");
    _errno = platform_driver_register(&fm_im_driver);
    if (unlikely(_errno < 0)) {
        pr_err(KBUILD_MODNAME
            ": %s:%hu:%s(): platform_driver_register() = %d\n",
            KBUILD_BASENAME".c", __LINE__, __func__, _errno);
    }

    return _errno;
}

static void __exit __cold fm_im_unload(void)
{
    printk(KBUILD_MODNAME ": -> %s:%s()\n", KBUILD_BASENAME".c", __func__);
    platform_driver_unregister(&fm_im_driver);
}

module_init(fm_im_load);
module_exit(fm_im_unload);
MODULE_DESCRIPTION("QorIQ FMAN Independent Mode Ethernet driver for NXP DPAA1.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("NXP Corporation");
