function o(s){return[...(/(^|\n)group\s*\{([\s\S]*?)\n\}/.exec(s)?.[2]??"").matchAll(/^\s*([A-Za-z_][\w-]*)\s*\{/gm)].map(n=>n[1])}const c=(s,a)=>({id:s.id,content:a});export{c,o as g};
