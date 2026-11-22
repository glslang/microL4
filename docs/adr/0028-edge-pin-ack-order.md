# 0028: A driver of an edge-triggered pin Acks before it services its device

Status: accepted, M7 (2026-11-22)

## Context

`docs/abi.md`, [IRQHandler](../abi.md#irqhandler), told every driver to
loop wait, service, Ack, and `docs/design.md` argued that an edge lost
while an I/O APIC pin is masked "comes after a signal the driver has not
yet handled". The M7 check of the `uart` design found a case where that is
false. An edge pin is masked by its second delivery before `Ack`
([Interrupts](../design.md#irqcontrol-and-irqhandler)), and both
deliveries' signals merge into one notification word. If a device cause
arises after the driver's last look at the device in that service, its
edge reaches a masked pin; an I/O APIC that drops edges on a masked pin
(the 82093AA does) loses it, the line stays asserted, the `Ack` that
follows opens the pin with no new edge to come, and no signal is pending.
The driver then waits for ever; for `uart`, input and held writes stop.

## Decision

- A driver of an edge-triggered I/O APIC pin loops **wait, Ack, service**.
  The `Ack` opens the pin before the driver's last look at the device, so
  every later cause raises an edge on an open pin; an edge that arrives
  during the service masks the pin again but leaves a signal, so the
  driver runs once more.
- A driver of a level-triggered pin keeps **wait, service, Ack**: the line
  stays asserted until the device is serviced, and the pin stays masked
  until then, as before.
- After `SetNotification` either driver Acks once and services its device
  once, as before.
- The kernel's behaviour is unchanged. This corrects the usage the ABI
  prescribes, so it is recorded here.

## Consequences

- `user/uart` (ISA IRQ 4, an edge pin) uses wait, Ack, service; its host
  tests include the old order losing an interrupt.
- Root fails the `console` scenario if IRQ 4 comes back level-triggered,
  since `uart`'s loop assumes an edge pin.
- M8 and M9 drivers choose their loop by their pin's trigger mode; MSI and
  SINT sources need no `Ack` order (their `Ack` does nothing).
