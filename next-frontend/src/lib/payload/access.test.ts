import type { Access, CollectionConfig, GlobalConfig } from "payload";
import {
  CMS_ROLES,
  canUpdateOwnCmsUser,
  canUseCms,
  hasCmsRole,
  userRoles,
  withCmsCollectionAccess,
  withCmsGlobalAccess,
} from "@/lib/payload/access";
import { payloadAuthConfig } from "@/auth.config";
import { Users } from "@/collections/Users";

const accessArgs = (user: { id: string; roles?: unknown } | null) =>
  ({ req: { user } }) as unknown as Parameters<Access>[0];

describe("Payload CMS access", () => {
  it.each(CMS_ROLES)("allows the %s role", async (role) => {
    expect(hasCmsRole({ roles: [role] })).toBe(true);
    expect(await canUseCms(accessArgs({ id: "1", roles: [role] }))).toBe(true);
  });

  it("rejects users without an approved role", async () => {
    expect(hasCmsRole({ roles: ["delegate"] })).toBe(false);
    expect(await canUseCms(accessArgs({ id: "1", roles: ["delegate"] }))).toBe(
      false,
    );
    expect(await canUseCms(accessArgs(null))).toBe(false);
  });

  it("ignores invalid role values", () => {
    expect(userRoles({ roles: ["wst", 1, null] })).toEqual(["wst"]);
    expect(userRoles({ roles: "wst" })).toEqual([]);
  });

  it("limits user updates to the approved current user", async () => {
    expect(
      await canUpdateOwnCmsUser(
        accessArgs({ id: "user-id", roles: ["delegate"] }),
      ),
    ).toBe(false);
    expect(
      await canUpdateOwnCmsUser(accessArgs({ id: "user-id", roles: ["wst"] })),
    ).toEqual({ id: { equals: "user-id" } });
  });

  it("adds CMS write rules to collections and preserves read rules", async () => {
    const read = () => true;
    const collection = withCmsCollectionAccess({
      slug: "example",
      fields: [],
      access: { read },
    } satisfies CollectionConfig);

    expect(collection.access?.read).toBe(read);
    expect(
      await collection.access?.create?.(
        accessArgs({ id: "1", roles: ["delegate"] }),
      ),
    ).toBe(false);
    expect(
      await collection.access?.create?.(
        accessArgs({ id: "1", roles: ["wst"] }),
      ),
    ).toBe(true);
  });

  it("preserves a stricter collection write rule", async () => {
    const collection = withCmsCollectionAccess({
      slug: "example",
      fields: [],
      access: { update: () => false },
    } satisfies CollectionConfig);

    expect(
      await collection.access?.update?.(
        accessArgs({ id: "1", roles: ["wst"] }),
      ),
    ).toBe(false);
  });

  it("adds CMS update rules to globals and preserves read rules", async () => {
    const read = () => true;
    const global = withCmsGlobalAccess({
      slug: "example",
      fields: [],
      access: { read },
    } satisfies GlobalConfig);

    expect(global.access?.read).toBe(read);
    expect(
      await global.access?.update?.(
        accessArgs({ id: "1", roles: ["delegate"] }),
      ),
    ).toBe(false);
    expect(
      await global.access?.update?.(accessArgs({ id: "1", roles: ["board"] })),
    ).toBe(true);
  });

  it("rejects a CMS sign-in without an approved role", async () => {
    const signIn = payloadAuthConfig.callbacks?.signIn;
    expect(signIn).toBeDefined();

    await expect(
      signIn?.({ profile: { roles: ["delegate"] } } as never),
    ).resolves.toBe(false);
    await expect(
      signIn?.({ profile: { roles: ["wct"] } } as never),
    ).resolves.toBe(true);
  });

  it.each(["email", "name", "image", "roles"])(
    "rejects client writes to the %s field",
    async (fieldName) => {
      const field = Users.fields.find(
        (candidate) => "name" in candidate && candidate.name === fieldName,
      );

      expect(field).toBeDefined();
      expect("access" in field!).toBe(true);
      if (field && "access" in field) {
        expect(await field.access?.create?.({} as never)).toBe(false);
        expect(await field.access?.update?.({} as never)).toBe(false);
      }
    },
  );
});
