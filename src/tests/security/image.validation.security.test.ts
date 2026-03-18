/**
 * Regression tests for M5 (MEDIUM): stored URL-scheme injection via `image`.
 *
 * Prior to the fix, `createUser` and `updateUser` stored the `image` field
 * verbatim. RealWorld frontends render this value in navigable contexts
 * (<a href> on the settings page), so a stored `javascript:` or `data:` URI
 * becomes an XSS payload delivered to every profile visitor.
 *
 * These tests lock in the allow-list: only http/https pass; empty/absent
 * values remain permitted so the Prisma schema default still applies.
 */

// MUST be first: registers jest.mock before auth.service loads prisma.
import prismaMock from '../prisma-mock';
import { createUser, updateUser } from '../../app/routes/auth/auth.service';

describe('Image URL scheme validation (M5 regression)', () => {
  const okUserRow = {
    id: 1,
    username: 'alice',
    email: 'alice@example.com',
    password: 'hashed',
    bio: null,
    image: null,
    demo: false,
  };

  beforeEach(() => {
    // @ts-expect-error — jest-mock-extended deep-mock vs Prisma recursive generics
    prismaMock.user.findUnique.mockResolvedValue(null);
    prismaMock.user.create.mockResolvedValue(okUserRow);
    prismaMock.user.update.mockResolvedValue(okUserRow);
  });

  describe('createUser', () => {
    const base = { username: 'alice', email: 'a@b.c', password: 'pw' };

    test.each([
      ['javascript:alert(document.cookie)', 'javascript:'],
      ['JaVaScRiPt:alert(1)', 'case-insensitive javascript:'],
      [
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'data: URI',
      ],
      ['vbscript:msgbox(1)', 'vbscript:'],
      ['file:///etc/passwd', 'file:'],
    ])('rejects %s (%s)', async (image) => {
      await expect(createUser({ ...base, image })).rejects.toMatchObject({
        errorCode: 422,
      });
      expect(prismaMock.user.create).not.toHaveBeenCalled();
    });

    test('rejects non-string image payloads', async () => {
      // Simulates ?image[startsWith]=x style injection reaching the body
      const payload = { ...base, image: { toString: () => 'https://evil' } };
      // @ts-expect-error — intentionally wrong type
      await expect(createUser(payload)).rejects.toMatchObject({
        errorCode: 422,
      });
      expect(prismaMock.user.create).not.toHaveBeenCalled();
    });

    test('accepts https URLs', async () => {
      await expect(
        createUser({ ...base, image: 'https://cdn.example.com/a.png' })
      ).resolves.toHaveProperty('token');
    });

    test('accepts http URLs', async () => {
      await expect(
        createUser({ ...base, image: 'http://cdn.example.com/a.png' })
      ).resolves.toHaveProperty('token');
    });

    test('accepts absent image (schema default applies)', async () => {
      await expect(createUser(base)).resolves.toHaveProperty('token');
    });

    test('accepts empty-string image (falsy — schema default applies)', async () => {
      await expect(createUser({ ...base, image: '' })).resolves.toHaveProperty(
        'token'
      );
    });
  });

  describe('updateUser', () => {
    test('rejects javascript: scheme on update', async () => {
      await expect(
        updateUser({ image: 'javascript:alert(1)' }, 1)
      ).rejects.toMatchObject({ errorCode: 422 });
      expect(prismaMock.user.update).not.toHaveBeenCalled();
    });

    test('rejects data: scheme on update', async () => {
      await expect(
        updateUser({ image: 'data:text/html,<script>alert(1)</script>' }, 1)
      ).rejects.toMatchObject({ errorCode: 422 });
      expect(prismaMock.user.update).not.toHaveBeenCalled();
    });

    test('accepts https on update', async () => {
      await expect(
        updateUser({ image: 'https://cdn.example.com/b.png' }, 1)
      ).resolves.toHaveProperty('token');
    });

    test('accepts update with no image field at all', async () => {
      await expect(updateUser({ bio: 'hello' }, 1)).resolves.toHaveProperty(
        'token'
      );
    });
  });
});
