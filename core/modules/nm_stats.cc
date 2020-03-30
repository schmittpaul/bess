#include "nm_stats.h"

#include "../utils/ip.h"
#include "../utils/time.h"

using bess::utils::be32_t;
using bess::utils::NM_Flowcache;
using bess::utils::ToIpv4Address;

const int STATS_OUT_INTERVAL = 5;

double lasttime = get_epoch_time();
NM_Flowcache NMFC;

CommandResponse nm_stats::Init(const bess::pb::EmptyArg &) {
  task_id_t tid;

  tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID)
    return CommandFailure(ENOMEM, "Context creation failed");

  return CommandSuccess();
}

struct task_result nm_stats::RunTask(Context *, bess::PacketBatch *, void *) {
  double now = get_epoch_time();
  double timediff = now - lasttime;
  if (timediff > STATS_OUT_INTERVAL) {
    printf("Timer: %f\n", now);
    lasttime = now;

    for (auto ii = NMFC.flowcache.begin(); ii != NMFC.flowcache.end(); ii++)
      printf("STATS: %s %s %d %d %d\n",
             ToIpv4Address(be32_t(ii->first.client_ip)).c_str(),
             ToIpv4Address(be32_t(ii->first.server_ip)).c_str(),
             ii->first.client_port, ii->first.server_port, ii->second->pkts);
    printf("*********************************\n");
  }

  return {.block = false, .packets = 0, .bits = 0};
}

ADD_MODULE(nm_stats, "nm_stats",
           "Implements netmicroscope code to print stream statistics")