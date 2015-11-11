/*
 * Cryptographic API.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/lzma.h>

struct lzma_ctx {
	CLzmaEncHandle *p;
	SizeT propsSize;
	Byte propsEncoded[LZMA_PROPS_SIZE];
};

static void lzma_free_workspace(struct lzma_ctx *ctx)
{
	LzmaEnc_Destroy(ctx->p, &lzma_alloc, &lzma_alloc);
}

static int lzma_alloc_workspace(struct lzma_ctx *ctx, CLzmaEncProps *props)
{
	SRes res;

	ctx->p = (CLzmaEncHandle *)LzmaEnc_Create(&lzma_alloc);
	if (ctx->p == NULL)
		return -ENOMEM;

	res = LzmaEnc_SetProps(ctx->p, props);
	if (res != SZ_OK) {
		lzma_free_workspace(ctx);
		return -EINVAL;
	}

	ctx->propsSize = sizeof(ctx->propsEncoded);
	res = LzmaEnc_WriteProperties(ctx->p, ctx->propsEncoded, &ctx->propsSize);
	if (res != SZ_OK) {
		lzma_free_workspace(ctx);
		return -EINVAL;
	}

	return 0;
}

static int lzma_init(struct crypto_tfm *tfm)
{
	struct lzma_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;
	CLzmaEncProps props;
	LzmaEncProps_Init(&props);

	props.dictSize = LZMA_BEST_DICT(0x2000);
	props.level = LZMA_BEST_LEVEL;
	props.lc = LZMA_BEST_LC;
	props.lp = LZMA_BEST_LP;
	props.pb = LZMA_BEST_PB;
	props.fb = LZMA_BEST_FB;

	ret = lzma_alloc_workspace(ctx, &props);
	return ret;
}

static void lzma_exit(struct crypto_tfm *tfm)
{
	struct lzma_ctx *ctx = crypto_tfm_ctx(tfm);

	lzma_free_workspace(ctx);
}

static int lzma_compress(struct crypto_tfm *tfm, const u8 *src,
			 unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct lzma_ctx *ctx = crypto_tfm_ctx(tfm);
	SizeT compress_size = (SizeT)(*dlen);
	int ret;

	ret = LzmaEnc_MemEncode(ctx->p, dst, &compress_size, src, slen,
				1, NULL, &lzma_alloc, &lzma_alloc);
	if (ret != SZ_OK)
		return -EINVAL;

	*dlen = (unsigned int)compress_size;
	return 0;
}

static int lzma_decompress(struct crypto_tfm *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct lzma_ctx *ctx = crypto_tfm_ctx(tfm);
	SizeT dl = (SizeT)*dlen;
	SizeT sl = (SizeT)slen;
	ELzmaStatus status;
	int ret;

	ret = LzmaDecode(dst, &dl, src, &sl, ctx->propsEncoded, ctx->propsSize,
			 LZMA_FINISH_END, &status, &lzma_alloc);

	if (ret != SZ_OK || status == LZMA_STATUS_NOT_FINISHED)
		return -EINVAL;

	*dlen = (unsigned int)dl;
	return 0;
}

static struct crypto_alg lzma_alg = {
	.cra_name		= "lzma",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct lzma_ctx),
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(lzma_alg.cra_list),
	.cra_init		= lzma_init,
	.cra_exit		= lzma_exit,
	.cra_u			= { .compress = {
	.coa_compress 		= lzma_compress,
	.coa_decompress  	= lzma_decompress } }
};

static int __init lzma_mod_init(void)
{
	return crypto_register_alg(&lzma_alg);
}

static void __exit lzma_mod_exit(void)
{
	crypto_unregister_alg(&lzma_alg);
}

module_init(lzma_mod_init);
module_exit(lzma_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LZMA Compression Algorithm");
