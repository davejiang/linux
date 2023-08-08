.. SPDX-License-Identifier: GPL-2.0
.. include:: <isonum.txt>

========================
KEYP Theory of Operation
========================

:Copyright: |copy| 2023, Intel Corporation

:Author: Dave Jiang <dave.jiang@intel.com>

KEYP TABLE
----------

Keyp Programming Table Reporting Structure (KEYP) is provided via ACPI for the
discovery of the Key Configuration Unit Register Block associated with each
Integrity and Data Encryption (IDE) capable Root Port instance. The KEYP table
provides one or more Key Configuration Unit Structures (KCUS). Each KCUS
provides the base address of the Key Configuration Unit (KCU) register block
and a list of Root Ports (RP) that the KCU covers.

The driver will create an instance for each KCU that is discovered. Each RP
discovered will be hashed into the global KEYP xarray using the
segment/bus/devfn as the key. The pointer to the KCU instance is the value
for the xarray entry. This allows the discovery of KCU for a given a PCI device
that supports IDE.

When ACPI calls acpi_pci_root_add(), a refcount is incremented on the KCU for
each RP discovered under its purview. A decremet happens when
acpi_pci_root_remove() is called. However since ACPI does not have an exit
routine, the code is setup such that when the last RP refcount is done, the
KCU is freed.

While incrementing the refcount, the RP is also configured for the IDE stream
ID range. The Root Complex IDE Programming Guide r1.01 [1] specifies that each
stream ID under the same KCU must be unique. The stream ID field in the PCIe
IDE control registers are 8-bits. Therefore the max number of stream IDs
possible is 256. However given the requirement of the KCU, the 256 streams
must be divided amongst all of the RPs covered by the KCU. The current code
implements a simple scheme that divides 256 by the number of total RPs under
the KCU. The ranges are split amongst the RPs during this enumeration. The
range is programmed into 'pci_dev->ide.stream_min' and
'pci_dev->ide.stream_max' of the RP pci_dev.

KCU Operations
--------------

'struct pci_ide_ops' expects two callback functions. (*->stream_create*) to
setup an IDE stream and (*->stream_shutdown*) to take down an IDE stream. The
KEYP driver provides those two callbacks for configure a standalone IDE stream
based on KEYP configurations.

keyp_stream_create()
~~~~~~~~~~~~~~~~~~~~
This callback setups up a standalone IDE link based on KEYP.

1. First a key package is allocate and consists of 6 keys of 256-bit
   (32-bytes). The keys are bytes randomly generated via
   get_random_bytes_wait(). Three sets of keys for transmit sub-streams and
   three sets of keys for receive sub-streams. Sub-streams are consisted of
   Posted, Non-posted, and Completion sub-streams.
2. A call into the PCI subsystem and in order to program the IDE configuration
   registers for the RP and the endpoint (EP). This includes the allocation
   of a stream ID by the PCI subsystem.
3. An available KCU stream configuration block is allocated for the stream to
   be programmed. The stream ID is is written to the KCU stream control
   register. All 6 keys are written to the allocated key slots in the KCU,
   primed, and selected.
4. All keys are sent to the EP via PCIe DOE exchange and activated.
5. Enable PCI IDE streams on RP and EP via the PCIe IDE config registers.
6. Enable IDE via KEYP stream control.
7. Queue 100ms delayed work to scramble the key slots when the keys are consumed.
8. Queue delayed operation for key refresh.

keyp_stream_teardown()
~~~~~~~~~~~~~~~~~~~~~~
1. Cancel all queued delayed work on workqueue.
2. Free key slots if they are not freed by delayed work.
3. Disable stream via PCIe IDE config register for RP and EP
4. Disable stream via KEYP stream block.
5. Release stream ID.


[1]: https://cdrdv2-public.intel.com/732838/732838_Root%20Complex%20IDE%20Programming%20Guide_Rev1_01.pdf
