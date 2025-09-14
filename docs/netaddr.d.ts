/* tslint:disable */
/* eslint-disable */
export function main(): void;
export class NetaddrAPI {
  free(): void;
  constructor();
  parseIP(addr_str: string): string;
  getIPInfo(addr_str: string): string;
  parseNetwork(network_str: string): string;
  parseMAC(mac_str: string): string;
  createIPSet(addresses: string): string;
  getNextIP(addr_str: string): string;
  getPrevIP(addr_str: string): string;
  subnetNetwork(network_str: string, new_prefix: number): string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_netaddrapi_free: (a: number, b: number) => void;
  readonly netaddrapi_parseIP: (a: number, b: number, c: number) => [number, number, number, number];
  readonly netaddrapi_getIPInfo: (a: number, b: number, c: number) => [number, number, number, number];
  readonly netaddrapi_parseNetwork: (a: number, b: number, c: number) => [number, number, number, number];
  readonly netaddrapi_parseMAC: (a: number, b: number, c: number) => [number, number, number, number];
  readonly netaddrapi_createIPSet: (a: number, b: number, c: number) => [number, number, number, number];
  readonly netaddrapi_getNextIP: (a: number, b: number, c: number) => [number, number, number, number];
  readonly netaddrapi_getPrevIP: (a: number, b: number, c: number) => [number, number, number, number];
  readonly netaddrapi_subnetNetwork: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly main: () => void;
  readonly netaddrapi_new: () => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_3: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
