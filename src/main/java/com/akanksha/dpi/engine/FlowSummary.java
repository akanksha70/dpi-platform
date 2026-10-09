package com.akanksha.dpi.engine;

import com.akanksha.dpi.model.AppType;
import com.akanksha.dpi.model.FiveTuple;

public record FlowSummary(FiveTuple key, AppType app, String sni,
                          long packets, long bytes, long droppedPackets, boolean blocked) {}