from django.contrib.contenttypes.models import ContentType

from nautobot.apps.jobs import Job, IntegerVar, ObjectVar, register_jobs
from nautobot.dcim.models import Location, Device, Manufacturer, DeviceType, Platform
from nautobot.extras.models import Status, Role

class NewHpcs(Job):
    class Meta:
        name = "New Hypercaches"
        description = "Create new Hypercache devices in Nautobot"
        field_order = ["location_name", "hpc_count", "hpc_model"]

    location_name = ObjectVar(
        description="Location of the new HPCs",
        model=Location
    )
       
    hpc_model = ObjectVar(
        description="Hypercache server model", model=DeviceType, query_params={"manufacturer_id": "$manufacturer"}
    )
    
    role = ObjectVar(model=Role, required=False)
    
    count = IntegerVar(
        description="Number of devices to add",
        default=1
    )
    
    platform = ObjectVar(
        model=Platform,
        description="Select the platform for the device"
    )

    def run(self, *, location_name, hpc_model, role, count, platform, manufacturer=None):
        STATUS_PLANNED = Status.objects.get(name="Planned")
        
        clli = location_name.name.split('_')[1]
        
        # Check existing devices to determine the starting number
        existing_devices = Device.objects.filter(location=location_name)
        base_number = 1000
        if role.name == "Market Linear Edge":
            if any(d.name.startswith(f"{clli}-ak-hpc1") for d in existing_devices):  # Check for any hpc1xxx
                base_number = 1100
        else:
            base_number = 1000
        
        # Determine the next available number
        numbers = [int(d.name.split('hpc')[1]) for d in existing_devices if 'hpc' in d.name]
        if base_number == 1100:
            # If we're starting from 1100, we don't want to consider numbers below 1100
            numbers = [num for num in numbers if num >= 1100]
        next_num = base_number + 1 if not numbers else max(numbers) + 1
        
        new_devices = []
        for _ in range(count):
            device_name = f"{clli}-ak-hpc{next_num}"
            device = Device(
                name=device_name,
                role=role,
                location=location_name,
                platform=platform,
                device_type=hpc_model,
                status=STATUS_PLANNED,
            )
            new_devices.append(device)
            next_num += 1
            
        for device in new_devices:
            device.save()
            self.logger.info("Created new hpc", extra={"object": device})

register_jobs(NewHpcs)
