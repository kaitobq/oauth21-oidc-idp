import { organizationClient } from "@/lib/rpc/clients";

export const organizationRepository = {
  async create(name: string, displayName: string) {
    const res = await organizationClient.createOrganization({
      name,
      displayName,
    });
    return res.organization;
  },

  async get(id: string) {
    const res = await organizationClient.getOrganization({ id });
    return res.organization;
  },

  async list(pageSize = 20, pageToken = "") {
    const res = await organizationClient.listOrganizations({
      pageSize,
      pageToken,
    });
    return {
      organizations: res.organizations,
      nextPageToken: res.nextPageToken,
    };
  },
};
