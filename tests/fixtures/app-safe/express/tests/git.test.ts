import { execFileSync } from 'child_process';

test('git is available', () => {
  expect(execFileSync('git', ['--version']).toString()).toContain('git');
  expect(/v(\d+)/.exec('v22')?.[1]).toBe('22');
});
