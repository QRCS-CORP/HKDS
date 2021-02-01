#include "hkds_queue.h"

void hkds_queue_destroy(hkds_queue_message_queue* ctx)
{
	qsc_queue_destroy(&ctx->state);
}

void hkds_queue_flush(hkds_queue_message_queue* ctx, uint8_t* output)
{
	qsc_queue_flush(&ctx->state, output);
}

void hkds_queue_initialize(hkds_queue_message_queue* ctx, size_t depth, size_t width, uint8_t* tag)
{
	ctx->tag = tag;
	qsc_queue_initialize(&ctx->state, depth, width);
}

void hkds_queue_pop(hkds_queue_message_queue* ctx, uint8_t* output, size_t outlen)
{
	if (ctx->state.position != 0)
	{
		qsc_queue_pop(&ctx->state, output, outlen);
	}
}

void hkds_queue_push(hkds_queue_message_queue* ctx, const uint8_t* output, size_t outlen)
{
	if (ctx->state.position != ctx->state.depth)
	{
		qsc_queue_push(&ctx->state, output, outlen, 0);
	}
}

bool hkds_queue_isfull(hkds_queue_message_queue* ctx)
{
	return qsc_queue_isfull(&ctx->state);
}

bool hkds_queue_isempty(hkds_queue_message_queue* ctx)
{
	return qsc_queue_isempty(&ctx->state);
}

size_t hkds_queue_count(hkds_queue_message_queue* ctx)
{
	return qsc_queue_items(&ctx->state);
}

/* block message extract */

size_t hkds_queue_extract_block_x8(hkds_queue_message_queue* ctx, uint8_t output[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE])
{
	size_t i;

	i = 0;

	if (ctx->state.position >= HKDS_CACHX8_DEPTH)
	{
		for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
		{
			qsc_queue_pop(&ctx->state, output[i], ctx->state.width);
		}
	}

	return i;
}

size_t hkds_queue_extract_block_x64(hkds_queue_message_queue* ctx, uint8_t output[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE])
{
	size_t i;
	size_t j;

	i = 0;
	j = 0;

	if (ctx->state.position >= HKDS_CACHX64_SIZE)
	{
		for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
		{
			for (j = 0; i < HKDS_CACHX8_DEPTH; ++j)
			{
				qsc_queue_pop(&ctx->state, output[i][j], ctx->state.width);
			}
		}
	}

	return (size_t)(i * j);
}

/* stream queue serialization */

size_t hkds_queue_extract_stream(hkds_queue_message_queue* ctx, uint8_t* stream, size_t items)
{
	size_t i;

	i = 0;

	if (ctx->state.position >= items)
	{
		for (i = 0; i < items; ++i)
		{
			qsc_queue_pop(&ctx->state, ((uint8_t*)stream + (i * ctx->state.width)), ctx->state.width);
		}
	}

	return i;
}
