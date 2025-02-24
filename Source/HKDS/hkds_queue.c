#include "hkds_queue.h"
#include "utils.h"

void hkds_message_queue_destroy(hkds_message_queue_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		for (size_t i = 0; i < ctx->state.depth; ++i)
		{
			if (ctx->state.queue[i] != NULL)
			{
				utils_memory_clear(ctx->state.queue[i], ctx->state.width);
				utils_memory_aligned_free(ctx->state.queue[i]);
			}
		}

		utils_memory_aligned_free(ctx->state.queue);
		utils_memory_clear((uint8_t*)ctx->state.tags, sizeof(ctx->state.tags));
		ctx->state.count = 0;
		ctx->state.depth = 0;
		ctx->state.position = 0;
		ctx->state.width = 0;
	}
}

void hkds_message_queue_flush(hkds_message_queue_state* ctx, uint8_t* output)
{
	assert(ctx != NULL);
	assert(output != NULL);

	if (ctx->state.queue != NULL)
	{
		for (size_t i = 0; i < ctx->state.position; ++i)
		{
			if (ctx->state.queue[i] != NULL)
			{
				utils_memory_copy((output + (i * ctx->state.width)), ctx->state.queue[i], ctx->state.width);
				utils_memory_clear(ctx->state.queue[i], ctx->state.width);
			}
		}

		ctx->state.count = 0;
		ctx->state.position = 0;
		utils_memory_clear((uint8_t*)ctx->state.tags, sizeof(ctx->state.tags));
	}
}

void hkds_message_queue_initialize(hkds_message_queue_state* ctx, size_t depth, size_t width, uint8_t* tag)
{
	assert(ctx != NULL);
	assert(depth != 0 && width != 0);

	ctx->state.queue = (uint8_t**)utils_memory_aligned_alloc(HKDS_QUEUE_ALIGNMENT, depth * sizeof(uint8_t*));

	if (ctx->state.queue != NULL)
	{
		ctx->tag = tag;

		for (size_t i = 0; i < depth; ++i)
		{
			ctx->state.queue[i] = utils_memory_aligned_alloc(HKDS_QUEUE_ALIGNMENT, width);

			if (ctx->state.queue[i] != NULL)
			{
				utils_memory_clear(ctx->state.queue[i], width);
			}
		}

		ctx->state.count = 0;
		ctx->state.depth = depth;
		ctx->state.position = 0;
		utils_memory_clear((uint8_t*)ctx->state.tags, HKDS_QUEUE_MAX_DEPTH);
		ctx->state.width = width;
	}
}

void hkds_message_queue_pop(hkds_message_queue_state* ctx, uint8_t* output, size_t outlen)
{
	assert(ctx != NULL);
	assert(output != NULL);
	assert(outlen != 0);

	uint64_t tag;

	tag = 0;

	if (ctx->state.position != 0)
	{

		if (!hkds_message_queue_empty(ctx) && outlen <= ctx->state.width)
		{
			utils_memory_copy(output, ctx->state.queue[0], outlen);
			utils_memory_clear(ctx->state.queue[0], ctx->state.width);
			tag = ctx->state.tags[ctx->state.position - 1];

			if (ctx->state.count > 1)
			{
				for (size_t i = 1; i < ctx->state.count; ++i)
				{
					utils_memory_copy(ctx->state.queue[i - 1], ctx->state.queue[i], ctx->state.width);
					ctx->state.tags[i - 1] = ctx->state.tags[i];
				}
			}

			utils_memory_clear(ctx->state.queue[ctx->state.position - 1], ctx->state.width);
			ctx->state.tags[ctx->state.position - 1] = 0;
			--ctx->state.count;
			--ctx->state.position;
		}
	}
}

void hkds_message_queue_push(hkds_message_queue_state* ctx, const uint8_t* input, size_t inplen)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(inplen != 0);

	if (ctx->state.position != ctx->state.depth)
	{
		uint64_t tag;

		tag = utils_integer_le8to64(ctx->tag);

		if (!hkds_message_queue_full(ctx) && inplen <= ctx->state.width)
		{
			utils_memory_copy(ctx->state.queue[ctx->state.position], input, inplen);
			ctx->state.tags[ctx->state.position] = tag;
			++ctx->state.position;
			++ctx->state.count;
		}
	}
}

bool hkds_message_queue_full(const hkds_message_queue_state* ctx)
{
	assert(ctx != NULL);

	bool res;

	res = false;

	if (ctx != NULL)
	{
		res = (bool)(ctx->state.count == ctx->state.depth);
	}

	return res;
}

bool hkds_message_queue_empty(const hkds_message_queue_state* ctx)
{
	assert(ctx != NULL);

	bool res;

	res = false;

	if (ctx != NULL)
	{
		res = (bool)(ctx->state.count == 0);
	}

	return res;
}

size_t hkds_message_queue_count(const hkds_message_queue_state* ctx)
{
	assert(ctx != NULL);

	size_t res;

	res = 0;

	if (ctx != NULL)
	{
		res = ctx->state.count;
	}

	return res;
}

/* block message extract */

size_t hkds_message_queue_extract_block_x8(hkds_message_queue_state* ctx, uint8_t output[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE])
{
	size_t i;

	i = 0;

	if (ctx->state.position >= HKDS_CACHX8_DEPTH)
	{
		for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
		{
			hkds_message_queue_pop(ctx, output[i], ctx->state.width);
		}
	}

	return i;
}

size_t hkds_message_queue_extract_block_x64(hkds_message_queue_state* ctx, uint8_t output[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE])
{
	size_t i;
	size_t j;

	i = 0;
	j = 0;

	if (ctx->state.position >= HKDS_CACHX64_SIZE)
	{
		for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
		{
			for (j = 0; j < HKDS_CACHX8_DEPTH; ++j)
			{
				hkds_message_queue_pop(ctx, output[i][j], ctx->state.width);
			}
		}
	}

	return (i * j);
}

/* stream queue serialization */

size_t hkds_message_queue_extract_stream(hkds_message_queue_state* ctx, uint8_t* stream, size_t items)
{
	size_t i;

	i = 0;

	if (ctx->state.position >= items)
	{
		for (i = 0; i < items; ++i)
		{
			hkds_message_queue_pop(ctx, (stream + (i * ctx->state.width)), ctx->state.width);
		}
	}

	return i;
}

