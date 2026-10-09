package com.akanksha.dpi.engine;

import com.akanksha.dpi.model.FiveTuple;

public final class WorkerSelector {
    private WorkerSelector() {}

    /** Both directions of a connection always pick the same worker; different flows spread evenly. */
    public static int select(FiveTuple key, int workers) {
        int h = key.canonical().hashCode();
        h ^= (h >>> 16);                 // ^ is XOR, >>> shifts right: mixes the high bits into the low bits
        return Math.floorMod(h, workers); // floorMod never returns a negative number (plain % can)
    }
}