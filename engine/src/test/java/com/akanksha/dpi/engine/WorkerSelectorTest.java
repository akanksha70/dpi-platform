package com.akanksha.dpi.engine;

import com.akanksha.dpi.model.FiveTuple;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WorkerSelectorTest {

    private static FiveTuple randomKey(Random rnd) {
        return new FiveTuple("192.168.1." + rnd.nextInt(254),
                "10.0." + rnd.nextInt(255) + "." + rnd.nextInt(255),
                1024 + rnd.nextInt(60000), 443, 6);
    }

    @Test
    void spreadsFlowsEvenlyAcrossAllWorkers() {
        // The C++ version used only 4 of 16 threads. Here every worker must get close to its fair share.
        for (int workers : new int[]{4, 16}) {
            int n = 10_000;
            int[] counts = new int[workers];
            Random rnd = new Random(42);
            for (int i = 0; i < n; i++) {
                counts[WorkerSelector.select(randomKey(rnd), workers)]++;
            }
            double fair = (double) n / workers;
            for (int c : counts) {
                assertTrue(c > fair * 0.8 && c < fair * 1.2,
                        workers + " workers: got " + c + " packets, fair share is " + fair);
            }
        }
    }

    @Test
    void bothDirectionsOfAConnectionGoToTheSameWorker() {
        Random rnd = new Random(7);
        for (int i = 0; i < 1000; i++) {
            FiveTuple k = randomKey(rnd);
            assertEquals(WorkerSelector.select(k, 8), WorkerSelector.select(k.reverse(), 8));
        }
    }
}