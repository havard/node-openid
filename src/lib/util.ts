export function isValidDate(d: any) {
    return d instanceof Date && !isNaN(d as unknown as number);
}

export function hasOwnProperty(obj: any, key: string) {
    return Object.prototype.hasOwnProperty.call(obj, key);
}