export function parseShellArgs(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let quote: "single" | "double" | null = null;
  let escaping = false;

  for (const char of input) {
    if (escaping) {
      current += char;
      escaping = false;
      continue;
    }

    if (char === "\\") {
      if (quote === "single") {
        current += char;
      } else {
        escaping = true;
      }
      continue;
    }

    if (quote === "single") {
      if (char === "'") {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (quote === "double") {
      if (char === '"') {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (char === "'") {
      quote = "single";
      continue;
    }
    if (char === '"') {
      quote = "double";
      continue;
    }

    if (/\s/.test(char)) {
      if (current.length > 0) {
        args.push(current);
        current = "";
      }
      continue;
    }

    current += char;
  }

  if (escaping) {
    throw new Error("Arguments end with a trailing escape character.");
  }
  if (quote !== null) {
    throw new Error("Arguments contain an unterminated quote.");
  }
  if (current.length > 0) {
    args.push(current);
  }

  return args;
}
