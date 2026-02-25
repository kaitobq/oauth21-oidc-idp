import { createClient } from "@connectrpc/connect";
import { OrganizationService } from "@/gen/organization/v1/organization_pb";
import { transport } from "./transport";

export const organizationClient = createClient(OrganizationService, transport);
