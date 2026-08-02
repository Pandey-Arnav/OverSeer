import test from "node:test";
import assert from "node:assert/strict";
import { parsePnputilUsbDevices, parseWindowsUsbDevices } from "./usb-monitor.ts";

test("Windows snapshot preserves removable storage and its Defender scan path", () => {
  const devices = parseWindowsUsbDevices(JSON.stringify([
    { Kind: "storage", DeviceID: "e:", VolumeName: "TEST USB", VolumeSerialNumber: "ABC123" },
  ]));

  assert.deepEqual(devices, [{
    key: "volume:abc123",
    name: "TEST USB",
    category: "usb_storage_device",
    bsdName: "E:",
  }]);
});

test("Windows snapshot recognizes a Flipper-style USB HID as a keyboard device", () => {
  const devices = parseWindowsUsbDevices(JSON.stringify([
    {
      Kind: "pnp",
      InstanceId: "HID\\VID_0483&PID_5750&MI_00\\7&TEST&0&0000",
      Name: "HID Keyboard Device",
      Class: "Keyboard",
      ContainerId: "{FLIPPER-CONTAINER}",
    },
  ]));

  assert.equal(devices.length, 1);
  assert.equal(devices[0]?.category, "usb_hid_device");
  assert.equal(devices[0]?.vendorId, "0483");
  assert.equal(devices[0]?.productId, "5750");
  assert.equal(devices[0]?.bsdName, null);
});

test("Windows snapshot classifies a USB network adapter separately", () => {
  const devices = parseWindowsUsbDevices(JSON.stringify({
    Kind: "pnp",
    InstanceId: "USB\\VID_0BDA&PID_8153\\001000001",
    Name: "USB GbE Family Controller",
    Class: "Net",
    ContainerId: "{NETWORK-CONTAINER}",
  }));

  assert.equal(devices.length, 1);
  assert.equal(devices[0]?.category, "usb_network_device");
});

test("Windows snapshot de-duplicates composite PnP interfaces by container ID", () => {
  const devices = parseWindowsUsbDevices(JSON.stringify([
    {
      Kind: "pnp",
      InstanceId: "USB\\VID_0483&PID_5750\\FLIPPER",
      Name: "USB Composite Device",
      Class: "USB",
      ContainerId: "{SAME-CONTAINER}",
    },
    {
      Kind: "pnp",
      InstanceId: "HID\\VID_0483&PID_5750&MI_00\\FLIPPER",
      Name: "HID Keyboard Device",
      Class: "Keyboard",
      ContainerId: "{SAME-CONTAINER}",
    },
  ]));

  assert.equal(devices.length, 1);
  assert.equal(devices[0]?.category, "usb_hid_device");
  assert.equal(devices[0]?.name, "HID Keyboard Device");
});

test("Windows snapshot ignores non-USB input devices and invalid volume records", () => {
  const devices = parseWindowsUsbDevices(JSON.stringify([
    { Kind: "pnp", InstanceId: "BTHENUM\\DEV_1234", Name: "Bluetooth Keyboard", Class: "Keyboard" },
    { Kind: "storage", DeviceID: "not-a-drive", VolumeName: "Invalid" },
  ]));

  assert.deepEqual(devices, []);
});

test("pnputil CSV recognizes the live Windows keyboard output shape", () => {
  const csv = [
    "InstanceId,DeviceDescription,ClassName,ClassGuid,ManufacturerName,Status,ProblemCode,ProblemStatus,DriverName,ExtensionDriverNames",
    '"HID\\VID_0483&PID_5750&MI_00\\7&FLIPPER&0&0000","HID Keyboard Device","Keyboard","{4d36e96b-e325-11ce-bfc1-08002be10318}","(Standard keyboards)","Started","","","keyboard.inf",""',
  ].join("\r\n");

  const devices = parsePnputilUsbDevices(csv);
  assert.equal(devices.length, 1);
  assert.equal(devices[0]?.category, "usb_hid_device");
  assert.equal(devices[0]?.key, "pnp:0483:5750");
});

test("pnputil CSV collapses a composite device's USB and HID interfaces", () => {
  const csv = [
    "InstanceId,DeviceDescription,ClassName,ClassGuid,ManufacturerName,Status,ProblemCode,ProblemStatus,DriverName,ExtensionDriverNames",
    '"USB\\VID_0483&PID_5750\\FLIPPER","USB Input Device","HIDClass","guid","manufacturer","Started","","","input.inf",""',
    '"HID\\VID_0483&PID_5750&MI_00\\FLIPPER","HID Keyboard Device","Keyboard","guid","manufacturer","Started","","","keyboard.inf",""',
  ].join("\n");

  const devices = parsePnputilUsbDevices(csv);
  assert.equal(devices.length, 1);
  assert.equal(devices[0]?.vendorId, "0483");
  assert.equal(devices[0]?.productId, "5750");
});

test("pnputil CSV handles quoted commas and ignores non-USB devices", () => {
  const csv = [
    "InstanceId,DeviceDescription,ClassName,ClassGuid,ManufacturerName,Status,ProblemCode,ProblemStatus,DriverName,ExtensionDriverNames",
    '"USB\\VID_0BDA&PID_8153\\001","USB Ethernet, 2.5GbE","Net","guid","Vendor, Inc.","Started","","","net.inf",""',
    '"ACPI\\IDEA0102\\1","Standard PS/2 Keyboard","Keyboard","guid","Microsoft","Started","","","keyboard.inf",""',
  ].join("\n");

  const devices = parsePnputilUsbDevices(csv);
  assert.equal(devices.length, 1);
  assert.equal(devices[0]?.name, "USB Ethernet, 2.5GbE");
  assert.equal(devices[0]?.category, "usb_network_device");
});
