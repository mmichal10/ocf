/*
 * Copyright(c) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_concurrency.h"
#include "../metadata/metadata_io.h"
#include "../ocf_priv.h"
#include "../ocf_request.h"
#include "../utils/utils_alock.h"
#include "../utils/utils_cache_line.h"

static int ocf_pio_lock_fast(struct ocf_alock *alock,
		struct ocf_request *req, int rw)
{
	ocf_cache_line_t entry = req->byte_position;;
	int ret = OCF_LOCK_ACQUIRED;
	int32_t id = 0;
	ENV_BUG_ON(rw != OCF_WRITE);

	ENV_BUG_ON(ocf_alock_is_index_locked(alock, req, id));

	if (ocf_alock_trylock_entry_wr(alock, entry))
		ocf_alock_mark_index_locked(alock, req, id, true);
	else
		ret = OCF_LOCK_NOT_ACQUIRED;

	return ret;
}

static int ocf_pio_lock_slow(struct ocf_alock *alock,
		struct ocf_request *req, int rw, ocf_req_async_lock_cb cmpl)
{
	int32_t id = 0;
	ocf_cache_line_t entry = req->byte_position;
	int ret = 0;
	ENV_BUG_ON(rw != OCF_WRITE);

	ENV_BUG_ON(ocf_alock_is_index_locked(alock, req, id));

	if (!ocf_alock_lock_one_wr(alock, entry, cmpl, req, id)) {
		/* lock not acquired and not added to wait list */
		ret = -OCF_ERR_NO_MEM;
	}

	return ret;
}

static struct ocf_alock_lock_cbs ocf_pio_conc_cbs = {
		.lock_entries_fast = ocf_pio_lock_fast,
		.lock_entries_slow = ocf_pio_lock_slow
};

int ocf_pio_async_lock(struct ocf_alock *alock, struct ocf_request *req,
		ocf_req_async_lock_cb cmpl)
{
	return ocf_alock_lock_wr(alock, req, cmpl);
}

void ocf_pio_async_unlock(struct ocf_alock *alock, struct ocf_request *req)
{
	ocf_cache_line_t entry = req->byte_position;
	int id = 0;

	if (!ocf_alock_is_index_locked(alock, req, id))
		return;

	ocf_alock_unlock_one_wr(alock, entry);

	ocf_alock_mark_index_locked(alock, req, id, false);
}

#define ALLOCATOR_NAME_FMT "ocf_%s_pio_conc"
#define ALLOCATOR_NAME_MAX (sizeof(ALLOCATOR_NAME_FMT) + OCF_CACHE_NAME_SIZE)

int ocf_pio_concurrency_init(struct ocf_alock **self, unsigned num_pages,
		ocf_cache_t cache)
{
	struct ocf_alock *alock;
	size_t base_size = ocf_alock_obj_size();
	char name[ALLOCATOR_NAME_MAX];
	int ret;

	ret = snprintf(name, sizeof(name), ALLOCATOR_NAME_FMT,
			ocf_cache_get_name(cache));
	if (ret < 0)
		return ret;
	if (ret >= ALLOCATOR_NAME_MAX)
		return -OCF_ERR_NO_MEM;

	alock = env_vzalloc(base_size);
	if (!alock)
		return -OCF_ERR_NO_MEM;

	ret = ocf_alock_init_inplace(alock, num_pages, name, &ocf_pio_conc_cbs, cache);
	if (ret) {
		env_free(alock);
		return ret;
	}

	*self = alock;
	return 0;
}

void ocf_pio_concurrency_deinit(struct ocf_alock **self)
{
	ocf_alock_deinit(self);
}
