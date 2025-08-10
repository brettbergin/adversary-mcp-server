// Simple TypeScript test file to bypass cache
import { exec } from 'child_process';

export function testCommandInjection(userInput: string) {
    // This should trigger a vulnerability
    exec(`ls ${userInput}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}
