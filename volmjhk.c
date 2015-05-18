///////////////////////////////////////////////////////////////////////////
//				VOLMJ Hook Filter Driver (Win2K)
//					2015.5.18.
//					sekim@mantech.co.kr
///////////////////////////////////////////////////////////////////////////

#include "volmjhk.h"



NTKERNELAPI
NTSTATUS
ObReferenceObjectByName (
    IN PUNICODE_STRING  ObjectName,
    IN ULONG            Attributes,
    IN PACCESS_STATE    PassedAccessState OPTIONAL,
    IN ACCESS_MASK      DesiredAccess OPTIONAL,
    IN POBJECT_TYPE     ObjectType OPTIONAL,
    IN KPROCESSOR_MODE  AccessMode,
    IN OUT PVOID        ParseContext OPTIONAL,
    OUT PVOID           *Object
);

extern POBJECT_TYPE* IoDriverObjectType;

/*
typedef NTSTATUS (*pOldMJCodeDispatchRequestHK) (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			);

pOldMJCodeDispatchRequestHK		oldMJCodeDispatchRequestHK	= NULL;
*/

DRIVER_OBJECT g_old_DriverObject;
PFAST_IO_DEVICE_CONTROL old_FastIoDeviceControl ;

NTSTATUS DriverFilter(DRIVER_OBJECT *old_DriverObject, BOOLEAN b_hook)
{
	UNICODE_STRING drv_name;
	NTSTATUS status;
	PDRIVER_OBJECT new_DriverObject;
	int i;

	RtlInitUnicodeString(&drv_name, L"\\Driver\\volmgr");

	status = ObReferenceObjectByName(&drv_name, OBJ_CASE_INSENSITIVE, (ULONG)NULL, 0,
		*IoDriverObjectType, KernelMode, (ULONG) NULL, &new_DriverObject);
	if (status != STATUS_SUCCESS) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "[volmjhk] hook_driver: ObReferenceObjectByName fail\n");
		return status;
	}

	ObDereferenceObject(new_DriverObject);  
	 
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		if (b_hook) {
			old_DriverObject->MajorFunction[i] = new_DriverObject->MajorFunction[i];
			new_DriverObject->MajorFunction[i] = VOLMJHKDriverDispatch;
			
		} else
			new_DriverObject->MajorFunction[i] = old_DriverObject->MajorFunction[i];
	}
	
	return STATUS_SUCCESS;	
}

NTSTATUS DriverEntry( 
			IN PDRIVER_OBJECT DriverObject,
			IN PUNICODE_STRING RegistryPath
			)
{
	NTSTATUS status = STATUS_SUCCESS;
	

	// Create device
	status = DeviceInit ( DriverObject, RegistryPath );

	if (status != STATUS_SUCCESS) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "[VOLMJHK] DriverEntry: DeviceInit: 0x%x\n", status);
		goto FAIL;
	}

	status = DriverFilter(&g_old_DriverObject, TRUE);
		
	return status;

FAIL:
	if (status != STATUS_SUCCESS) {
		  
	}

    return status;

}
typedef struct _DEVICE_EXTENSION {
	unsigned int aaa;
}DEVICE_EXTENSION,*PDEVICE_EXTENSION;

NTSTATUS DeviceInit ( 
			IN PDRIVER_OBJECT DriverObject,
			IN PUNICODE_STRING RegistryPath
			)
{
	UNICODE_STRING	DeviceName;
	UNICODE_STRING	SymbolicLinkName;
	PDEVICE_OBJECT	DeviceObject;
	
	NTSTATUS		Status = STATUS_SUCCESS;	

	// Initialize device name string
   	RtlInitUnicodeString ( &DeviceName, L"\\Device\\VOLMJHK" );
	
	// Create new device
	Status = IoCreateDevice (
				DriverObject,
				sizeof(DEVICE_EXTENSION),
				&DeviceName,
				FILE_DEVICE_NETWORK,
				0,
				TRUE,
				&DeviceObject
				);

	if ( Status == STATUS_SUCCESS ) {
		// Create symbolic link for device
		RtlInitUnicodeString ( &SymbolicLinkName, L"\\DosDevices\\VOLMJHK" );

		IoCreateSymbolicLink ( &SymbolicLinkName, &DeviceName );

		DriverObject->MajorFunction [ IRP_MJ_CREATE ] = VOLMJHKOpenClose;
		DriverObject->MajorFunction [ IRP_MJ_CLOSE ] = VOLMJHKOpenClose;
//		DriverObject->MajorFunction [ IRP_MJ_CLEANUP ] = VOLMJHKOpenClose;
		DriverObject->MajorFunction [IRP_MJ_DEVICE_CONTROL] = VOLMJHKDispatchRequest;

		DriverObject->DriverUnload = OnUnload;
	}

	return Status;
}

NTSTATUS VOLMJHKDispatchRequest (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			)
{
	NTSTATUS			Status = STATUS_SUCCESS;
//	PUCHAR				pBuffer;
//	DWORD				InputBufferLength, OutputBufferLength, ControlCode, ReturnedSize = 0;
    PIO_STACK_LOCATION  irpStack = IoGetCurrentIrpStackLocation ( Irp );

	Irp -> IoStatus.Status = Status;
	Irp -> IoStatus.Information = 0;

	IoCompleteRequest ( Irp, IO_NO_INCREMENT );

	return Status;
}

NTSTATUS VOLMJHKOpenClose (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			)
{
	Irp -> IoStatus.Status = STATUS_SUCCESS;
    Irp -> IoStatus.Information = 0;

    IoCompleteRequest ( Irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}

VOID OnUnload(
			  IN PDRIVER_OBJECT DriverObject
			  )
{
	NTSTATUS status;
	UNICODE_STRING	SymbolicLinkName;

	status = DriverFilter(&g_old_DriverObject, FALSE);

	RtlInitUnicodeString ( &SymbolicLinkName, L"\\DosDevices\\VOLMJHK" );
	IoDeleteSymbolicLink(&SymbolicLinkName);

	IoDeleteDevice(DriverObject->DeviceObject);
	
}


NTSTATUS
VOLMJHKDriverDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
	PIO_STACK_LOCATION		irps;
	NTSTATUS				status;
	PUCHAR					Buffer = NULL;

	// sanity check
	if (irp == NULL) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF,"[VOLMJHK] DriverDispatch: !irp\n");
		return STATUS_SUCCESS;
	}
	irps = IoGetCurrentIrpStackLocation(irp);

	if(0x85ec25c8 == (unsigned int)DeviceObject) { //HarddiskVolume3 block TEST
		irp ->IoStatus.Status = STATUS_ACCESS_DENIED;
    	irp ->IoStatus.Information = 0;
    	IoCompleteRequest ( irp, IO_NO_INCREMENT );
    	return STATUS_UNSUCCESSFUL;;
	}
	
	// Analyze MajorFunction
	switch (irps->MajorFunction) {
		
	case IRP_MJ_CREATE:
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF,"[VOLMJHK] DriverDispatch: IRP_MJ_CREATE\n");
		break;
	case IRP_MJ_CLEANUP:
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF,"[VOLMJHK] DriverDispatch: IRP_MJ_CLEANUP\n");
		break;
	case IRP_MJ_CLOSE:	
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF,"[VOLMJHK] DriverDispatch: IRP_MJ_CLOSE\n");
		break;
	case IRP_MJ_INTERNAL_DEVICE_CONTROL: 
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF,"[VOLMJHK] DriverDispatch: IRP_MJ_INTERNAL_DEVICE_CONTROL\n");
		break;	
	case IRP_MJ_READ:
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF,"[VOLMJHK] DriverDispatch: IRP_MJ_READ\n");
		break;
	case IRP_MJ_WRITE:
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF,"[VOLMJHK] DriverDispatch: IRP_MJ_WRITE\n");
		break;
	case IRP_MJ_DEVICE_CONTROL:
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF,"[VOLMJHK] DriverDispatch: IRP_MJ_DEVICE_CONTROL\n");
		break;
			
	default:
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF,"[VOLMJHK] DriverDispatch: major 0x%x, minor 0x%x for 0x%x\n", irps->MajorFunction, irps->MinorFunction, irps->FileObject);

	}
		
	status = g_old_DriverObject.MajorFunction[irps->MajorFunction](DeviceObject, irp);
	
	return status;

}


