import { describe, expect, it, vi } from 'vitest';
import {
  validateDcoRange,
  validateGithubPullRequest
} from '../scripts/validate-dco.mjs';

const base = '1'.repeat(40);
const head = '2'.repeat(40);
const first = '3'.repeat(40);
const second = '4'.repeat(40);

describe('DCO range validation', () => {
  it('accepts every commit when sign-off email matches its author', () => {
    const runGit = vi.fn(
      fixtureGit([
        commit(first, 'First Author', 'first@example.invalid'),
        commit(second, 'Second Author', 'second@example.invalid')
      ])
    );
    expect(validateDcoRange(base, head, { runGit })).toEqual({ commits: 2 });
    expect(runGit).toHaveBeenCalledWith([
      'rev-list',
      '--reverse',
      `${base}..${head}`
    ]);
  });

  it('rejects a sign-off whose name does not match the author', () => {
    const runGit = fixtureGit([
      commit(
        first,
        'Contributor',
        'contributor@example.invalid',
        'Different Name <contributor@example.invalid>'
      )
    ]);
    expect(() => validateDcoRange(base, head, { runGit })).toThrow(
      'author-matching DCO sign-off'
    );
  });

  it('rejects an unsigned commit even when a later commit is signed', () => {
    const runGit = fixtureGit([
      commit(first, 'First Author', 'first@example.invalid', null),
      commit(second, 'Second Author', 'second@example.invalid')
    ]);
    expect(() => validateDcoRange(base, head, { runGit })).toThrow(first.slice(0, 12));
  });

  it('rejects a sign-off belonging to a different email identity', () => {
    const runGit = fixtureGit([
      commit(first, 'Author', 'author@example.invalid', 'Author <other@example.invalid>')
    ]);
    expect(() => validateDcoRange(base, head, { runGit })).toThrow(
      'author-matching DCO sign-off'
    );
  });

  it('rejects non-SHA range input before invoking Git', () => {
    const runGit = vi.fn<(_: string[]) => string>();
    expect(() =>
      validateDcoRange('HEAD~1;touch-pwned', head, { runGit })
    ).toThrow('full lowercase Git commit SHAs');
    expect(runGit).not.toHaveBeenCalled();
  });

  it('rejects a standalone range whose base is not an ancestor', () => {
    const runGit = (args: string[]) => {
      if (args[0] === 'cat-file') return '';
      if (args[0] === 'merge-base') throw new Error('base is not an ancestor');
      throw new Error(`unexpected git invocation: ${args.join(' ')}`);
    };
    expect(() => validateDcoRange(base, head, { runGit })).toThrow(
      'base is not an ancestor'
    );
  });

  it('validates GitHub PR metadata without executing the candidate tree', async () => {
    const fetchImpl = vi.fn((input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer read-token');
      if (url === 'https://api.github.com/repos/example/project/pulls/17') {
        return Promise.resolve(new Response(JSON.stringify({ commits: 1 })));
      }
      expect(url).toBe(
        'https://api.github.com/repos/example/project/pulls/17/commits?per_page=100&page=1'
      );
      return Promise.resolve(
        new Response(
          JSON.stringify([
            {
              sha: first,
              commit: {
                author: { name: 'Contributor', email: 'contributor@example.invalid' },
                committer: { name: 'Forged Committer', email: 'forged@example.invalid' },
                message:
                  'fixture\n\nSigned-off-by: Contributor <contributor@example.invalid>\n'
              }
            }
          ])
        )
      );
    });
    await expect(
      validateGithubPullRequest('example/project', '17', {
        fetchImpl,
        token: 'read-token'
      })
    ).resolves.toEqual({ commits: 1 });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('fails closed when GitHub cannot return the complete PR commit set', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(new Response(JSON.stringify({ commits: 251 })))
    );
    await expect(
      validateGithubPullRequest('example/project', '18', {
        fetchImpl,
        token: 'read-token'
      })
    ).rejects.toThrow('between 1 and 250 commits for complete DCO review');
    expect(fetchImpl).toHaveBeenCalledOnce();
  });
});

function commit(
  sha: string,
  authorName: string,
  authorEmail: string,
  signoff: string | null = `${authorName} <${authorEmail}>`
) {
  const message = signoff ? `fixture\n\nSigned-off-by: ${signoff}\n` : 'fixture\n';
  return {
    sha,
    metadata: [authorName, authorEmail, message].join('\0')
  };
}

function fixtureGit(commits: Array<{ sha: string; metadata: string }>) {
  return (args: string[]) => {
    if (args[0] === 'cat-file') return '';
    if (args[0] === 'merge-base') return '';
    if (args[0] === 'rev-list') return `${commits.map(({ sha }) => sha).join('\n')}\n`;
    if (args[0] === 'show') {
      const match = commits.find(({ sha }) => sha === args.at(-1));
      if (match) return match.metadata;
    }
    throw new Error(`unexpected git invocation: ${args.join(' ')}`);
  };
}
