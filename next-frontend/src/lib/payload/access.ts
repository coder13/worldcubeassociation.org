import type { Access, CollectionConfig, GlobalConfig } from "payload";

export const CMS_ROLES = ["wst", "wct", "wat", "wmt", "board"] as const;

type UserWithRoles = {
  id?: number | string | null;
  roles?: unknown;
};

export function userRoles(user: UserWithRoles | null | undefined): string[] {
  if (!Array.isArray(user?.roles)) {
    return [];
  }

  return user.roles.filter((role): role is string => typeof role === "string");
}

export function hasCmsRole(user: UserWithRoles | null | undefined): boolean {
  const roles = userRoles(user);
  return CMS_ROLES.some((role) => roles.includes(role));
}

export const canUseCms: Access = ({ req: { user } }) => hasCmsRole(user);

function requireCmsRole(access?: Access): Access {
  return async (args) => {
    if (!hasCmsRole(args.req.user)) {
      return false;
    }

    return access ? await access(args) : true;
  };
}

export const canUpdateOwnCmsUser: Access = ({ req: { user } }) => {
  if (!user || !hasCmsRole(user)) {
    return false;
  }

  return {
    id: {
      equals: user.id,
    },
  };
};

export function withCmsCollectionAccess(
  collection: CollectionConfig,
): CollectionConfig {
  return {
    ...collection,
    access: {
      ...collection.access,
      create: requireCmsRole(collection.access?.create),
      update: requireCmsRole(collection.access?.update),
      delete: requireCmsRole(collection.access?.delete),
      readVersions: requireCmsRole(collection.access?.readVersions),
      unlock: requireCmsRole(collection.access?.unlock),
    },
  };
}

export function withCmsGlobalAccess(global: GlobalConfig): GlobalConfig {
  return {
    ...global,
    access: {
      ...global.access,
      update: requireCmsRole(global.access?.update),
      readVersions: requireCmsRole(global.access?.readVersions),
    },
  };
}
