# zschema sub-schema for zgrab2's memcache module
# Registers zgrab2-memcached globally, and memcached with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

response = SubRecord(
    {
        "result": SubRecord(
            {
                "version": String(doc="Version of the Memcached server"),
                "libevent_version": String(
                    doc="Version of the libevent library used by the Memcached server"
                ),
                "supports_ascii": Boolean(
                    doc="Whether the server supports plain-text ASCII commands"
                ),
                "supports_binary": Boolean(
                    doc="Whether the server supports binary commands"
                ),
                "stats": SubRecord(
                    {
                        "pid": Unsigned32BitInteger(),
                        "uptime": Unsigned32BitInteger(),
                        "time": Unsigned32BitInteger(),
                        "pointer_size": Signed32BitInteger(),
                        "rusage_user": Float(),
                        "rusage_system": Float(),
                        "curr_items": Unsigned32BitInteger(),
                        "total_items": Unsigned32BitInteger(),
                        "bytes": Unsigned32BitInteger(),
                        "max_connections": Unsigned32BitInteger(),
                        "curr_connections": Unsigned32BitInteger(),
                        "total_connections": Unsigned32BitInteger(),
                        "rejected_connections": Unsigned32BitInteger(),
                        "connected_structures": Unsigned32BitInteger(),
                        "response_obj_oom": Unsigned32BitInteger(),
                        "response_obj_count": Unsigned32BitInteger(),
                        "response_obj_bytes": Unsigned32BitInteger(),
                        "read_buf_count": Unsigned32BitInteger(),
                        "read_buf_bytes": Unsigned32BitInteger(),
                        "read_buf_bytes_free": Unsigned32BitInteger(),
                        "read_buf_oom": Unsigned32BitInteger(),
                        "reserved_fds": Unsigned32BitInteger(),
                        "proxy_conn_requests": Unsigned32BitInteger(),
                        "proxy_conn_errors": Unsigned32BitInteger(),
                        "proxy_conn_oom": Unsigned32BitInteger(),
                        "proxy_req_active": Unsigned32BitInteger(),
                        "proxy_req_await": Unsigned32BitInteger(),
                        "cmd_get": Unsigned32BitInteger(),
                        "cmd_set": Unsigned32BitInteger(),
                        "cmd_flush": Unsigned32BitInteger(),
                        "cmd_touch": Unsigned32BitInteger(),
                        "get_hits": Unsigned32BitInteger(),
                        "get_misses": Unsigned32BitInteger(),
                        "get_expired": Unsigned32BitInteger(),
                        "get_flushed": Unsigned32BitInteger(),
                        "delete_misses": Unsigned32BitInteger(),
                        "delete_hits": Unsigned32BitInteger(),
                        "incr_misses": Unsigned32BitInteger(),
                        "incr_hits": Unsigned32BitInteger(),
                        "decr_misses": Unsigned32BitInteger(),
                        "decr_hits": Unsigned32BitInteger(),
                        "cas_misses": Unsigned32BitInteger(),
                        "cas_hits": Unsigned32BitInteger(),
                        "cas_badval": Unsigned32BitInteger(),
                        "touch_hits": Unsigned32BitInteger(),
                        "touch_misses": Unsigned32BitInteger(),
                        "store_too_large": Unsigned32BitInteger(),
                        "store_no_memory": Unsigned32BitInteger(),
                        "auth_cmds": Unsigned32BitInteger(),
                        "auth_errors": Unsigned32BitInteger(),
                        "idle_kicks": Unsigned32BitInteger(),
                        "evictions": Unsigned32BitInteger(),
                        "reclaimed": Unsigned32BitInteger(),
                        "bytes_read": Unsigned32BitInteger(),
                        "bytes_written": Unsigned32BitInteger(),
                        "limit_maxbytes": Unsigned32BitInteger(),
                        "accepting_conns": Boolean(),
                        "listen_disabled_num": Unsigned32BitInteger(),
                        "time_in_listen_disabled_us": Unsigned32BitInteger(),
                        "threads": Unsigned32BitInteger(),
                        "conn_yields": Unsigned32BitInteger(),
                        "hash_power_level": Unsigned32BitInteger(),
                        "hash_bytes": Unsigned32BitInteger(),
                        "hash_is_expanding": Boolean(),
                        "expired_unfetched": Unsigned32BitInteger(),
                        "evicted_unfetched": Unsigned32BitInteger(),
                        "evicted_active": Unsigned32BitInteger(),
                        "slab_reassign_running": Boolean(),
                        "slabs_moved": Unsigned32BitInteger(),
                        "crawler_reclaimed": Unsigned32BitInteger(),
                        "crawler_items_checked": Unsigned32BitInteger(),
                        "lrutail_reflocked": Unsigned32BitInteger(),
                        "moves_to_cold": Unsigned32BitInteger(),
                        "moves_to_warm": Unsigned32BitInteger(),
                        "moves_within_lru": Unsigned32BitInteger(),
                        "direct_reclaims": Unsigned32BitInteger(),
                        "lru_crawler_starts": Unsigned32BitInteger(),
                        "lru_maintainer_juggles": Unsigned32BitInteger(),
                        "slab_global_page_pool": Unsigned32BitInteger(),
                        "slab_reassign_rescues": Unsigned32BitInteger(),
                        "slab_reassign_chunk_rescues": Unsigned32BitInteger(),
                        "slab_reassign_inline_reclaim": Unsigned32BitInteger(),
                        "slab_reassign_busy_items": Unsigned32BitInteger(),
                        "slab_reassign_busy_nomem": Unsigned32BitInteger(),
                        "slab_reassign_busy_deletes": Unsigned32BitInteger(),
                        "log_worker_dropped": Unsigned32BitInteger(),
                        "log_worker_written": Unsigned32BitInteger(),
                        "log_watcher_skipped": Unsigned32BitInteger(),
                        "log_watcher_sent": Unsigned32BitInteger(),
                        "log_watchers": Unsigned32BitInteger(),
                        "unexpected_napi_ids": Unsigned32BitInteger(),
                        "round_robin_fallback": Unsigned32BitInteger(),
                    }
                ),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-memcached", response)

zgrab2.register_scan_response_type("memcached", response)
