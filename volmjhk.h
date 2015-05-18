#ifndef __VOLMJHK_H__
#define __VOLMJHK_H__

#include <ntddk.h>


NTSTATUS VOLMJHKDispatchRequest ( 
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			);
NTSTATUS VOLMJHKOpenClose (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			);

NTSTATUS DeviceInit (
			IN PDRIVER_OBJECT DriverObject,
			IN PUNICODE_STRING RegistryPath
			);

VOID OnUnload(
			  IN PDRIVER_OBJECT DriverObject
			  );

NTSTATUS DriverFilter(
			IN DRIVER_OBJECT *old_DriverObject, 
			IN BOOLEAN b_hook
			);

NTSTATUS	VOLMJHKDriverDispatch (
			IN PDEVICE_OBJECT DeviceObject, 
			IN PIRP irp
			);


#endif