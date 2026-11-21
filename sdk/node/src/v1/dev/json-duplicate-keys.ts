// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Report whether JSON text that `JSON.parse` accepted repeats a decoded key
 * within one object. `JSON.parse` keeps the last duplicate silently.
 */
export function hasDuplicateJsonKeys(json: string): boolean {
  // One entry per open container: the keys seen so far, or null for an array.
  const stack: Array<Set<string> | null> = [];
  let expectKey = false;
  for (let index = 0; index < json.length; index += 1) {
    const char = json[index];
    if (char === '"') {
      const start = index;
      for (index += 1; index < json.length && json[index] !== '"'; index += 1) {
        if (json[index] === '\\') index += 1;
      }
      const keys = stack.at(-1);
      if (keys && expectKey) {
        const key = JSON.parse(json.slice(start, index + 1)) as string;
        if (keys.has(key)) return true;
        keys.add(key);
        expectKey = false;
      }
    } else if (char === '{' || char === '[') {
      stack.push(char === '{' ? new Set() : null);
      expectKey = char === '{';
    } else if (char === '}' || char === ']') {
      stack.pop();
      expectKey = false;
    } else if (char === ',') {
      expectKey = Boolean(stack.at(-1));
    }
  }
  return false;
}
