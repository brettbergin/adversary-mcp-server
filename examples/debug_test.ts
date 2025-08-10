// Debug test file to check MCP parameter handling
import { exec } from 'child_process';

export function vulnerabilityTest(input: string) {
    exec(`echo ${input}`, () => {});
}
