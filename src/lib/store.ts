export abstract class Store<Key extends string | number | symbol, Value> {
    abstract getItem(key: Key): (Value | undefined) | Promise<Value | undefined>;
    abstract setItem(key: Key, value: Value): this | Promise<this>;
    abstract removeItem(key: Key): this | Promise<this>;
    abstract getAll(): Record<Key, Value> | Promise<Record<Key, Value>>;
}