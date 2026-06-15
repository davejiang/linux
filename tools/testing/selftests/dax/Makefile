# SPDX-License-Identifier: GPL-2.0
CFLAGS += -Wall -O2

all:

TEST_GEN_FILES := private_node_tool

TEST_PROGS := dax-kmem-hotplug.sh \
	      private_node_hotplug.sh \
	      private_node_isolation.sh \
	      private_node_ltpin.sh \
	      private_node_pressure.sh \
	      private_node_reclaim.sh \
	      private_node_cpuset.sh \
	      private_node_observability.sh \
	      private_node_demotion.sh \
	      private_node_mbind.sh \
	      private_node_mempolicy.sh \
	      private_node_user_migrate.sh

include ../lib.mk
