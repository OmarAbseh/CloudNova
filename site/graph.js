/* Attack-path graph, the hero animation.
 *
 * Hand-written on a 2D canvas with a small perspective projection rather than
 * pulling in a 3D library. Three reasons: the page stays self-contained so the
 * hero cannot break because a CDN is blocked, the whole file is smaller than
 * the library would be, and what is drawn here is a specific thing rather than
 * a generic mesh.
 *
 * What it draws is the product. CloudNova's differentiator is chaining single
 * findings into an exploitable path, so the hero shows a cloud estate as a
 * graph and traces a real path through it: something exposed to the internet,
 * reaching an over-privileged identity, reaching data. The mouse steers the
 * camera.
 */
(function () {
  "use strict";

  var canvas = document.getElementById("graph");
  if (!canvas || !canvas.getContext) return;
  var ctx = canvas.getContext("2d");
  if (!ctx) return;

  var reduceMotion =
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Node kinds carry the meaning, so colour is never the only signal: the
  // path readout underneath names each hop in words.
  var KIND = {
    edge:    { color: "#ff6b81", r: 5.5, label: "internet facing" },
    compute: { color: "#8b8b99", r: 4.5, label: "compute" },
    identity:{ color: "#ffb02e", r: 5.0, label: "identity" },
    data:    { color: "#3ddc84", r: 5.5, label: "data store" }
  };

  // A small, deliberately shaped estate. Hand-placed rather than random so the
  // traced path reads as a plausible chain every time.
  var nodes = [
    { id: 0, k: "edge",     p: [-1.5,  0.75, 0.35], n: "alb-public" },
    { id: 1, k: "compute",  p: [-0.55, 0.95, -0.3], n: "ecs-web" },
    { id: 2, k: "compute",  p: [-0.75, -0.1,  0.7], n: "ec2-worker" },
    { id: 3, k: "identity", p: [ 0.25, 0.35, -0.1], n: "role/app" },
    { id: 4, k: "identity", p: [ 0.55, -0.6,  0.5], n: "role/admin" },
    { id: 5, k: "data",     p: [ 1.55, 0.1,  -0.35], n: "s3/customer-data" },
    { id: 6, k: "data",     p: [ 1.35, -0.85, 0.2], n: "rds/billing" },
    { id: 7, k: "compute",  p: [-0.2, -1.0, -0.55], n: "lambda-cron" },
    { id: 8, k: "compute",  p: [ 0.1,  1.15, 0.6],  n: "eks-api" },
    { id: 9, k: "identity", p: [-1.2, -0.75, -0.5], n: "user/ci" }
  ];

  var edges = [
    [0, 1], [0, 8], [1, 3], [8, 3], [2, 3], [3, 5],
    [2, 4], [4, 5], [4, 6], [7, 4], [9, 2], [1, 2], [7, 6]
  ];

  // The chain the animation walks. Each hop is a real escalation step.
  var PATHS = [
    { hops: [0, 1, 3, 5], why: "public load balancer, web task, app role, customer data" },
    { hops: [9, 2, 4, 6], why: "CI user, worker host, admin role, billing database" },
    { hops: [0, 8, 3, 5], why: "public load balancer, Kubernetes API, app role, customer data" }
  ];

  var adj = {};
  edges.forEach(function (e) {
    (adj[e[0]] = adj[e[0]] || []).push(e[1]);
    (adj[e[1]] = adj[e[1]] || []).push(e[0]);
  });

  var W = 0, H = 0, dpr = 1;
  function resize() {
    var rect = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = Math.max(1, Math.round(rect.width));
    H = Math.max(1, Math.round(rect.height));
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resize();
  window.addEventListener("resize", resize);

  // Mouse steers the camera. Values are targets; the render loop eases toward
  // them so the motion never snaps.
  var yawTarget = 0, pitchTarget = 0, yaw = 0, pitch = 0;
  var hovering = false;

  function pointerTo(x, y) {
    var rect = canvas.getBoundingClientRect();
    var nx = (x - rect.left) / rect.width - 0.5;
    var ny = (y - rect.top) / rect.height - 0.5;
    yawTarget = nx * 1.5;
    pitchTarget = -ny * 0.9;
  }

  var host = canvas.parentNode || canvas;
  host.addEventListener("mousemove", function (e) {
    hovering = true;
    pointerTo(e.clientX, e.clientY);
  });
  host.addEventListener("mouseleave", function () {
    hovering = false;
    yawTarget = 0;
    pitchTarget = 0;
  });
  host.addEventListener(
    "touchmove",
    function (e) {
      if (e.touches && e.touches.length) {
        hovering = true;
        pointerTo(e.touches[0].clientX, e.touches[0].clientY);
      }
    },
    { passive: true }
  );

  function project(p, spin) {
    // Yaw about Y, then pitch about X, then a simple perspective divide.
    var cy = Math.cos(yaw + spin), sy = Math.sin(yaw + spin);
    var x = p[0] * cy - p[2] * sy;
    var z = p[0] * sy + p[2] * cy;
    var cp = Math.cos(pitch), sp = Math.sin(pitch);
    var y = p[1] * cp - z * sp;
    z = p[1] * sp + z * cp;

    var dist = 4.2;
    var scale = (Math.min(W, H) * 0.42) / (dist - z);
    return {
      x: W / 2 + x * scale,
      y: H / 2 - y * scale,
      s: scale / (Math.min(W, H) * 0.42),
      z: z
    };
  }

  // Path animation state.
  var pathIndex = 0;
  var pathProgress = 0;
  var holdUntil = 0;
  var readout = document.getElementById("graph-path");

  function currentPathEdges() {
    var hops = PATHS[pathIndex].hops;
    var pairs = [];
    for (var i = 0; i < hops.length - 1; i++) pairs.push([hops[i], hops[i + 1]]);
    return pairs;
  }

  function setReadout(text) {
    if (readout && readout.textContent !== text) readout.textContent = text;
  }

  var start = performance.now();
  var lastFrame = start;

  function frame(now) {
    var dt = Math.min((now - lastFrame) / 1000, 0.05);
    lastFrame = now;

    // Ease the camera toward the pointer, and drift slowly when idle so the
    // hero is never completely static.
    yaw += (yawTarget - yaw) * Math.min(dt * 4, 1);
    pitch += (pitchTarget - pitch) * Math.min(dt * 4, 1);
    var spin = hovering || reduceMotion ? 0 : ((now - start) / 1000) * 0.06;

    ctx.clearRect(0, 0, W, H);

    var pts = nodes.map(function (nd) {
      return project(nd.p, spin);
    });

    // Advance the traced path.
    var pathPairs = currentPathEdges();
    if (!reduceMotion) {
      if (now > holdUntil) {
        pathProgress += dt * 0.55;
        if (pathProgress >= pathPairs.length + 1.2) {
          pathProgress = 0;
          pathIndex = (pathIndex + 1) % PATHS.length;
          holdUntil = now + 450;
        }
      }
    } else {
      pathProgress = pathPairs.length;
    }
    setReadout(PATHS[pathIndex].why);

    var litEdge = {};
    pathPairs.forEach(function (pair, i) {
      if (pathProgress > i) litEdge[pair[0] + "-" + pair[1]] = Math.min(pathProgress - i, 1);
    });

    // Base edges first, back to front, so nearer lines sit on top.
    var ordered = edges
      .map(function (e) {
        return { e: e, z: (pts[e[0]].z + pts[e[1]].z) / 2 };
      })
      .sort(function (a, b) {
        return a.z - b.z;
      });

    ordered.forEach(function (item) {
      var a = pts[item.e[0]], b = pts[item.e[1]];
      var key = item.e[0] + "-" + item.e[1];
      var litFwd = litEdge[key];
      var litRev = litEdge[item.e[1] + "-" + item.e[0]];
      var lit = litFwd !== undefined ? litFwd : litRev;

      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = "rgba(140,140,160,0.16)";
      ctx.lineWidth = 1;
      ctx.stroke();

      if (lit !== undefined) {
        // Draw the lit portion as a partial line so the path appears to travel.
        var ex = a.x + (b.x - a.x) * lit;
        var ey = a.y + (b.y - a.y) * lit;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(ex, ey);
        ctx.strokeStyle = "rgba(255,46,77,0.95)";
        ctx.lineWidth = 2;
        ctx.shadowColor = "rgba(255,46,77,0.7)";
        ctx.shadowBlur = 8;
        ctx.stroke();
        ctx.shadowBlur = 0;
      }
    });

    // Nodes on top, scaled by depth.
    var onPath = {};
    PATHS[pathIndex].hops.forEach(function (h, i) {
      if (pathProgress >= i) onPath[h] = true;
    });

    nodes
      .map(function (nd, i) {
        return { nd: nd, pt: pts[i] };
      })
      .sort(function (a, b) {
        return a.pt.z - b.pt.z;
      })
      .forEach(function (item) {
        var kind = KIND[item.nd.k];
        var r = kind.r * (0.65 + item.pt.s * 0.5);
        var hot = onPath[item.nd.id];

        ctx.beginPath();
        ctx.arc(item.pt.x, item.pt.y, r, 0, Math.PI * 2);
        ctx.fillStyle = hot ? "#ff2e4d" : kind.color;
        ctx.globalAlpha = hot ? 1 : 0.55 + item.pt.s * 0.3;
        ctx.fill();
        ctx.globalAlpha = 1;

        // A surface ring keeps overlapping nodes legible.
        ctx.beginPath();
        ctx.arc(item.pt.x, item.pt.y, r, 0, Math.PI * 2);
        ctx.strokeStyle = "#0a0a0d";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        if (hot) {
          ctx.beginPath();
          ctx.arc(item.pt.x, item.pt.y, r + 4, 0, Math.PI * 2);
          ctx.strokeStyle = "rgba(255,46,77,0.45)";
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      });

    raf = requestAnimationFrame(frame);
  }

  // Stop painting when the tab is hidden or the hero scrolls away; an
  // animation nobody can see is just battery.
  var raf = null;
  function play() {
    if (raf === null) {
      lastFrame = performance.now();
      raf = requestAnimationFrame(frame);
    }
  }
  function pause() {
    if (raf !== null) {
      cancelAnimationFrame(raf);
      raf = null;
    }
  }
  document.addEventListener("visibilitychange", function () {
    document.hidden ? pause() : play();
  });
  if ("IntersectionObserver" in window) {
    new IntersectionObserver(function (entries) {
      entries[0].isIntersecting ? play() : pause();
    }).observe(canvas);
  }
  play();
})();
