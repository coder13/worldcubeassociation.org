import type { CollectionConfig } from "payload";
import {
  canUpdateOwnCmsUser,
  hasCmsRole,
  userRoles,
} from "@/lib/payload/access";

const denyClientWrite = () => false;

export const Users: CollectionConfig = {
  slug: "users",
  admin: {
    useAsTitle: "name",
  },
  fields: [
    {
      name: "email",
      type: "email",
      admin: {
        readOnly: true,
      },
      access: {
        create: denyClientWrite,
        update: denyClientWrite,
      },
    },
    {
      name: "name",
      type: "text",
      admin: {
        readOnly: true,
      },
      access: {
        create: denyClientWrite,
        update: denyClientWrite,
      },
    },
    {
      name: "image",
      type: "text",
      admin: {
        readOnly: true,
      },
      access: {
        create: denyClientWrite,
        update: denyClientWrite,
      },
    },
    {
      name: "roles",
      type: "json",
      jsonSchema: {
        uri: "a://b/foo.json", // required
        fileMatch: ["a://b/foo.json"], // required
        schema: {
          type: "array",
          items: {
            type: "string",
          },
        },
      },
      admin: {
        hidden: true,
      },
      access: {
        create: denyClientWrite,
        update: denyClientWrite,
      },
    },
  ],
  access: {
    admin: ({ req: { user } }) => hasCmsRole(user),
    create: denyClientWrite,
    update: canUpdateOwnCmsUser,
    delete: denyClientWrite,
    readVersions: denyClientWrite,
    unlock: denyClientWrite,
    read: ({ req: { user } }) => {
      if (!user) {
        return false;
      }

      if (userRoles(user).includes("wst_admin")) {
        // Admins are allowed to see all users
        return true;
      }

      if (!hasCmsRole(user)) {
        return false;
      }

      return {
        // Only allow to read the current user, ie "yourself"
        id: {
          equals: user.id,
        },
      };
    },
  },
};
