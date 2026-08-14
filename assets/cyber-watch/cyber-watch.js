(function () {
    'use strict';

    // Every event, address, count and route in this scene is intentionally synthetic.
    // The IP addresses use RFC 5737 documentation ranges and do not identify real hosts.
    var scene = document.getElementById('cyberWatchScene');
    var canvas = document.getElementById('cyberThreatCanvas');
    var mapSvg = document.getElementById('cyberMapSvg');
    var countryLayer = document.getElementById('cyberMapCountries');
    var gridLayer = document.getElementById('cyberMapGrid');
    if (!scene || !canvas || !mapSvg || !countryLayer || !gridLayer) return;

    var context = canvas.getContext('2d', { alpha: true, desynchronized: true });
    if (!context) return;

    var VIEW = { width: 1920, height: 1080 };
    var MAP = { x: 92, y: 146, width: 1736, height: 720 };
    var SVG_NS = 'http://www.w3.org/2000/svg';
    var reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    var reducedMotion = reducedMotionQuery.matches;
    var numberFormat = new Intl.NumberFormat('en-GB');

    var elements = {
        feed: document.getElementById('cyberEventList'),
        clock: document.getElementById('cyberUtcClock'),
        total: document.getElementById('cyberTotalEvents'),
        blocked: document.getElementById('cyberBlockedEvents'),
        active: document.getElementById('cyberActiveRoutes'),
        nodes: document.getElementById('cyberNodesOnline'),
        threat: document.getElementById('cyberThreatLevel'),
        meter: document.getElementById('cyberThreatMeter'),
        response: document.getElementById('cyberResponseTime'),
        packetRate: document.getElementById('cyberPacketRate'),
        sweep: document.getElementById('cyberScanSweep'),
        loading: document.getElementById('cyberLoading'),
        a11yStatus: document.getElementById('cyberA11yStatus')
    };

    var eventTypes = [
        { key: 'probe', label: 'PROBE', colour: '#2dd4ff', severity: ['LOW', 'LOW', 'MED'] },
        { key: 'intrusion', label: 'EXPLOIT', colour: '#9c6cff', severity: ['MED', 'HIGH'] },
        { key: 'malware', label: 'MALWARE', colour: '#ff3bd4', severity: ['MED', 'HIGH'] },
        { key: 'critical', label: 'DDoS', colour: '#ff4d6d', severity: ['HIGH', 'CRIT'] },
        { key: 'blocked', label: 'BLOCKED', colour: '#36f3a1', severity: ['LOW', 'MED'] },
        { key: 'probe', label: 'CREDENTIAL', colour: '#ffc857', severity: ['MED', 'HIGH'] }
    ];

    var protocols = ['TCP/443', 'TCP/22', 'UDP/53', 'TCP/8080', 'TLS/1.3', 'QUIC/443', 'TCP/3389', 'UDP/1194'];
    var documentationBlocks = [
        [192, 0, 2],
        [198, 51, 100],
        [203, 0, 113]
    ];

    var nodes = [
        ['YVR', -123.12, 49.28], ['SEA', -122.33, 47.61], ['SFO', -122.42, 37.77],
        ['LAX', -118.24, 34.05], ['DFW', -96.80, 32.78], ['CHI', -87.63, 41.88],
        ['YUL', -73.57, 45.50], ['NYC', -74.01, 40.71], ['MIA', -80.19, 25.76],
        ['MEX', -99.13, 19.43], ['PTY', -79.52, 8.98], ['BOG', -74.07, 4.71],
        ['LIM', -77.04, -12.05], ['SAO', -46.63, -23.55], ['SCL', -70.67, -33.45],
        ['BUE', -58.38, -34.60], ['DUB', -6.26, 53.35], ['LHR', -0.13, 51.51],
        ['LIS', -9.14, 38.72], ['MAD', -3.70, 40.42], ['CDG', 2.35, 48.86],
        ['AMS', 4.90, 52.37], ['FRA', 8.68, 50.11], ['WAW', 21.01, 52.23],
        ['HEL', 24.94, 60.17], ['MOW', 37.62, 55.76], ['IST', 28.98, 41.01],
        ['CAI', 31.24, 30.04], ['LOS', 3.38, 6.52], ['NBO', 36.82, -1.29],
        ['JNB', 28.05, -26.20], ['CPT', 18.42, -33.93], ['TLV', 34.78, 32.09],
        ['DXB', 55.27, 25.20], ['BOM', 72.88, 19.08], ['DEL', 77.21, 28.61],
        ['BLR', 77.59, 12.97], ['BKK', 100.50, 13.76], ['SIN', 103.82, 1.35],
        ['JKT', 106.85, -6.21], ['HKG', 114.17, 22.32], ['PEK', 116.41, 39.90],
        ['SHA', 121.47, 31.23], ['MNL', 120.98, 14.60], ['SEL', 126.98, 37.57],
        ['TYO', 139.69, 35.68], ['PER', 115.86, -31.95], ['MEL', 144.96, -37.81],
        ['SYD', 151.21, -33.87], ['AKL', 174.76, -36.85]
    ].map(function (node, index) {
        var point = project(node[1], node[2]);
        return { code: node[0], lon: node[1], lat: node[2], x: point.x, y: point.y, phase: index * 0.71 };
    });

    var routes = [];
    var bursts = [];
    var animationFrame = 0;
    var nextSpawnAt = 0;
    var lastStatsAt = 0;
    var lastClockAt = 0;
    var idleTimer = 0;
    var totalEvents = 8492116;
    var blockedEvents = 8471834;
    var mapReady = false;
    var isVisible = !document.hidden;

    function project(lon, lat) {
        var northernLimit = 85;
        var southernLimit = -60;
        var boundedLatitude = clamp(lat, southernLimit, northernLimit);
        return {
            x: MAP.x + ((lon + 180) / 360) * MAP.width,
            y: MAP.y + ((northernLimit - boundedLatitude) / (northernLimit - southernLimit)) * MAP.height
        };
    }

    function randomBetween(min, max) {
        return min + Math.random() * (max - min);
    }

    function randomItem(items) {
        return items[Math.floor(Math.random() * items.length)];
    }

    function clamp(value, min, max) {
        return Math.max(min, Math.min(max, value));
    }

    function hexToRgb(hex) {
        var raw = hex.replace('#', '');
        return {
            r: parseInt(raw.slice(0, 2), 16),
            g: parseInt(raw.slice(2, 4), 16),
            b: parseInt(raw.slice(4, 6), 16)
        };
    }

    function rgba(hex, alpha) {
        var rgb = hexToRgb(hex);
        return 'rgba(' + rgb.r + ',' + rgb.g + ',' + rgb.b + ',' + clamp(alpha, 0, 1) + ')';
    }

    function makeSvgElement(name, attributes) {
        var element = document.createElementNS(SVG_NS, name);
        Object.keys(attributes || {}).forEach(function (key) {
            element.setAttribute(key, String(attributes[key]));
        });
        return element;
    }

    function renderMapGrid() {
        var fragment = document.createDocumentFragment();
        for (var lon = -150; lon <= 150; lon += 30) {
            var x = project(lon, 0).x;
            fragment.appendChild(makeSvgElement('line', {
                x1: x, y1: MAP.y, x2: x, y2: MAP.y + MAP.height,
                class: 'cyber-map-grid-line' + (lon % 60 === 0 ? ' is-major' : '')
            }));
        }
        for (var lat = -60; lat <= 60; lat += 20) {
            var y = project(0, lat).y;
            fragment.appendChild(makeSvgElement('line', {
                x1: MAP.x, y1: y, x2: MAP.x + MAP.width, y2: y,
                class: 'cyber-map-grid-line' + (lat === 0 || lat % 40 === 0 ? ' is-major' : '')
            }));
        }
        gridLayer.replaceChildren(fragment);
    }

    function ringToPath(ring) {
        var path = '';
        var previousX = null;
        var started = false;
        ring.forEach(function (coordinate) {
            if (!Array.isArray(coordinate) || coordinate.length < 2) return;
            var point = project(Number(coordinate[0]), Number(coordinate[1]));
            var crossesDateLine = previousX !== null && Math.abs(point.x - previousX) > MAP.width * 0.45;
            path += (!started || crossesDateLine ? 'M' : 'L') + point.x.toFixed(2) + ',' + point.y.toFixed(2);
            previousX = point.x;
            started = true;
        });
        return path;
    }

    function geometryToPath(geometry) {
        if (!geometry || !geometry.coordinates) return '';
        var polygons = geometry.type === 'Polygon'
            ? [geometry.coordinates]
            : geometry.type === 'MultiPolygon' ? geometry.coordinates : [];
        return polygons.map(function (polygon) {
            return polygon.map(ringToPath).join('');
        }).join('');
    }

    function renderCountries(geojson) {
        if (!geojson || !Array.isArray(geojson.features)) throw new Error('Invalid map data');
        var fragment = document.createDocumentFragment();
        geojson.features.forEach(function (feature, index) {
            var name = feature.properties && (feature.properties.ADMIN || feature.properties.NAME || feature.properties.name);
            if (name && String(name).toLowerCase() === 'antarctica') return;
            var pathData = geometryToPath(feature.geometry);
            if (!pathData) return;
            var path = makeSvgElement('path', {
                d: pathData,
                class: 'cyber-map-country',
                'fill-rule': 'evenodd',
                'data-map-index': index
            });
            if (name) path.setAttribute('aria-label', String(name));
            fragment.appendChild(path);
        });
        countryLayer.replaceChildren(fragment);
        mapReady = true;
    }

    function loadMap() {
        renderMapGrid();
        var mapUrl = scene.getAttribute('data-map-url') || 'assets/cyber-watch/world-110m.geojson';
        return fetch(mapUrl, { credentials: 'omit', cache: 'force-cache' })
            .then(function (response) {
                if (!response.ok) throw new Error('Map request failed with ' + response.status);
                return response.json();
            })
            .then(function (data) {
                renderCountries(data);
                finishLoading('Simulated global telemetry scene ready.');
            })
            .catch(function () {
                mapReady = false;
                finishLoading('Simulation running with simplified map grid.');
            });
    }

    function finishLoading(message) {
        window.setTimeout(function () {
            scene.classList.add('is-ready');
            if (elements.loading) elements.loading.classList.add('is-hidden');
        }, 420);
        if (elements.a11yStatus) elements.a11yStatus.textContent = message;
    }

    function resizeCanvas() {
        var bounds = canvas.getBoundingClientRect();
        if (bounds.width < 2 || bounds.height < 2) return;
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = Math.max(1, Math.round(bounds.width * dpr));
        canvas.height = Math.max(1, Math.round(bounds.height * dpr));
        context.setTransform(
            canvas.width / VIEW.width,
            0,
            0,
            canvas.height / VIEW.height,
            0,
            0
        );
        context.lineCap = 'round';
        context.lineJoin = 'round';
    }

    function documentationIp() {
        var block = randomItem(documentationBlocks);
        return block.join('.') + '.' + Math.floor(randomBetween(1, 255));
    }

    function nodeIdentity(node) {
        return 'NODE-' + node.code + '-' + String(Math.floor(randomBetween(1, 32))).padStart(2, '0');
    }

    function createEventRow(route) {
        if (!elements.feed) return;
        var item = document.createElement('li');
        var time = document.createElement('time');
        var type = document.createElement('span');
        var routeText = document.createElement('span');
        var severity = document.createElement('span');
        var now = new Date();
        var origin = nodeIdentity(route.origin) + ' [' + documentationIp() + ']';
        var target = nodeIdentity(route.destination) + ' [' + documentationIp() + ']';

        item.className = 'cyber-event is-' + route.type.key;
        item.dataset.type = route.type.key;
        item.dataset.severity = route.severity === 'CRIT' ? 'critical' : route.severity.toLowerCase();
        item.style.setProperty('--event-color', route.type.colour);

        time.className = 'cyber-event__time';
        time.dateTime = now.toISOString();
        time.textContent = now.toISOString().slice(11, 19);

        type.className = 'cyber-event__type';
        type.textContent = route.type.label;

        routeText.className = 'cyber-event__route';
        routeText.textContent = origin + ' → ' + target + ' · ' + route.protocol;
        routeText.title = routeText.textContent;

        severity.className = 'cyber-event__severity';
        severity.textContent = route.severity;

        item.append(time, type, routeText, severity);
        elements.feed.prepend(item);
        while (elements.feed.children.length > 9) {
            elements.feed.lastElementChild.remove();
        }
    }

    function chooseRouteNodes() {
        var origin = randomItem(nodes);
        var destination = randomItem(nodes);
        var attempts = 0;
        while ((destination === origin || Math.abs(destination.x - origin.x) < 105) && attempts < 20) {
            destination = randomItem(nodes);
            attempts += 1;
        }
        return { origin: origin, destination: destination };
    }

    function spawnRoute(now, seedAge) {
        var pair = chooseRouteNodes();
        var type = randomItem(eventTypes);
        var dx = pair.destination.x - pair.origin.x;
        var dy = pair.destination.y - pair.origin.y;
        var distance = Math.sqrt(dx * dx + dy * dy);
        var direction = Math.random() < 0.86 ? -1 : 1;
        var lift = clamp(62 + distance * randomBetween(0.08, 0.17), 72, 250) * direction;
        var duration = reducedMotion ? randomBetween(6200, 8600) : randomBetween(4400, 7600);
        var route = {
            origin: pair.origin,
            destination: pair.destination,
            type: type,
            severity: randomItem(type.severity),
            protocol: randomItem(protocols),
            bornAt: now - (seedAge || 0) * duration,
            duration: duration,
            controlX: (pair.origin.x + pair.destination.x) / 2 + randomBetween(-38, 38),
            controlY: (pair.origin.y + pair.destination.y) / 2 + lift,
            width: randomBetween(0.9, 1.7),
            phase: Math.random() * Math.PI * 2,
            fed: Boolean(seedAge)
        };
        routes.push(route);
        if (!route.fed) createEventRow(route);
        if (routes.length > (reducedMotion ? 12 : 36)) routes.shift();
        return route;
    }

    function bezierPoint(route, t) {
        var oneMinus = 1 - t;
        return {
            x: oneMinus * oneMinus * route.origin.x + 2 * oneMinus * t * route.controlX + t * t * route.destination.x,
            y: oneMinus * oneMinus * route.origin.y + 2 * oneMinus * t * route.controlY + t * t * route.destination.y
        };
    }

    function traceRoute(route, from, to, steps) {
        var first = bezierPoint(route, from);
        context.beginPath();
        context.moveTo(first.x, first.y);
        for (var i = 1; i <= steps; i += 1) {
            var point = bezierPoint(route, from + ((to - from) * i) / steps);
            context.lineTo(point.x, point.y);
        }
    }

    function drawPulse(point, colour, progress, destination) {
        if (progress < 0 || progress > 1) return;
        var radius = (destination ? 8 : 4) + progress * (destination ? 38 : 26);
        var alpha = (1 - progress) * (destination ? 0.8 : 0.55);
        context.beginPath();
        context.arc(point.x, point.y, radius, 0, Math.PI * 2);
        context.strokeStyle = rgba(colour, alpha);
        context.lineWidth = destination ? 1.4 : 1;
        context.shadowBlur = destination ? 18 : 10;
        context.shadowColor = colour;
        context.stroke();
    }

    function drawNodes(now) {
        nodes.forEach(function (node, index) {
            var wave = 0.5 + Math.sin(now * 0.0014 + node.phase) * 0.5;
            var alpha = 0.15 + wave * 0.32;
            context.beginPath();
            context.arc(node.x, node.y, index % 5 === 0 ? 2.3 : 1.45, 0, Math.PI * 2);
            context.fillStyle = 'rgba(122,226,255,' + alpha.toFixed(3) + ')';
            context.shadowBlur = 6 + wave * 7;
            context.shadowColor = '#2dd4ff';
            context.fill();
        });
    }

    function drawRoute(route, now) {
        var age = (now - route.bornAt) / route.duration;
        var head = clamp(age * 1.09, 0, 1);
        var fadeIn = clamp(age / 0.12, 0, 1);
        var fadeOut = clamp((1.16 - age) / 0.18, 0, 1);
        var alpha = fadeIn * fadeOut;
        var colour = route.type.colour;

        traceRoute(route, 0, head, 42);
        context.strokeStyle = rgba(colour, 0.075 * alpha);
        context.lineWidth = route.width * 8.5;
        context.shadowBlur = 24;
        context.shadowColor = colour;
        context.stroke();

        traceRoute(route, 0, head, 54);
        context.strokeStyle = rgba(colour, 0.57 * alpha);
        context.lineWidth = route.width;
        context.shadowBlur = 10;
        context.shadowColor = colour;
        context.stroke();

        var tailStart = Math.max(0, head - 0.17);
        var previous = bezierPoint(route, tailStart);
        for (var step = 1; step <= 18; step += 1) {
            var t = tailStart + ((head - tailStart) * step) / 18;
            var point = bezierPoint(route, t);
            context.beginPath();
            context.moveTo(previous.x, previous.y);
            context.lineTo(point.x, point.y);
            context.strokeStyle = rgba(colour, alpha * (step / 18) * 0.95);
            context.lineWidth = route.width * (0.7 + step / 12);
            context.shadowBlur = 9;
            context.shadowColor = colour;
            context.stroke();
            previous = point;
        }

        var comet = bezierPoint(route, head);
        context.beginPath();
        context.arc(comet.x, comet.y, route.width * 2.3 + 1.1, 0, Math.PI * 2);
        context.fillStyle = rgba('#ffffff', 0.92 * alpha);
        context.shadowBlur = 18;
        context.shadowColor = colour;
        context.fill();

        drawPulse(route.origin, colour, age / 0.28, false);
        drawPulse(route.destination, colour, (age - 0.78) / 0.28, true);

        if (age >= 0.84 && !route.burstCreated) {
            route.burstCreated = true;
            bursts.push({ x: route.destination.x, y: route.destination.y, colour: colour, bornAt: now });
        }
        return age < 1.18;
    }

    function drawBursts(now) {
        bursts = bursts.filter(function (burst) {
            var progress = (now - burst.bornAt) / 850;
            if (progress >= 1) return false;
            var rays = reducedMotion ? 4 : 8;
            context.save();
            context.translate(burst.x, burst.y);
            context.rotate(progress * 0.9);
            for (var ray = 0; ray < rays; ray += 1) {
                var angle = (Math.PI * 2 * ray) / rays;
                var inner = 5 + progress * 7;
                var outer = 12 + progress * 38;
                context.beginPath();
                context.moveTo(Math.cos(angle) * inner, Math.sin(angle) * inner);
                context.lineTo(Math.cos(angle) * outer, Math.sin(angle) * outer);
                context.strokeStyle = rgba(burst.colour, (1 - progress) * 0.7);
                context.lineWidth = 1;
                context.shadowBlur = 9;
                context.shadowColor = burst.colour;
                context.stroke();
            }
            context.restore();
            return true;
        });
    }

    function updateClock(now) {
        if (!elements.clock || now - lastClockAt < 45) return;
        lastClockAt = now;
        var date = new Date();
        var iso = date.toISOString();
        elements.clock.textContent = iso.slice(0, 10) + '  ' + iso.slice(11, 23) + 'Z';
        elements.clock.dateTime = iso;
    }

    function updateStats(now) {
        if (now - lastStatsAt < 310) return;
        var seconds = lastStatsAt ? (now - lastStatsAt) / 1000 : 0.31;
        lastStatsAt = now;
        var eventDelta = Math.floor(randomBetween(2150, 3480) * seconds);
        totalEvents += eventDelta;
        blockedEvents += Math.floor(eventDelta * randomBetween(0.994, 0.999));
        var intensity = clamp(35 + routes.length * 2.05 + randomBetween(-3, 8), 28, 96);
        var threatLabel = intensity > 82 ? 'CRITICAL' : intensity > 62 ? 'ELEVATED' : intensity > 45 ? 'GUARDED' : 'NOMINAL';

        if (elements.total) elements.total.textContent = numberFormat.format(totalEvents);
        if (elements.blocked) elements.blocked.textContent = numberFormat.format(blockedEvents);
        if (elements.active) elements.active.textContent = String(routes.length).padStart(2, '0');
        if (elements.nodes) elements.nodes.textContent = numberFormat.format(1482 + Math.floor(randomBetween(-4, 5)));
        if (elements.threat) elements.threat.textContent = threatLabel;
        if (elements.meter) {
            elements.meter.style.setProperty('--cyber-threat-level', intensity.toFixed(1) + '%');
            elements.meter.style.width = intensity.toFixed(1) + '%';
        }
        if (elements.response) elements.response.textContent = randomBetween(14.2, 24.8).toFixed(1) + ' ms';
        if (elements.packetRate) elements.packetRate.textContent = randomBetween(2.42, 3.18).toFixed(2) + 'M';
    }

    function animate(now) {
        animationFrame = window.requestAnimationFrame(animate);
        updateClock(now);
        if (!isVisible) return;

        var spawnDelay = reducedMotion ? randomBetween(1150, 1750) : randomBetween(145, 430);
        if (now >= nextSpawnAt) {
            spawnRoute(now, 0);
            nextSpawnAt = now + spawnDelay;
        }

        context.clearRect(0, 0, VIEW.width, VIEW.height);
        context.save();
        context.globalCompositeOperation = 'lighter';
        drawNodes(now);
        routes = routes.filter(function (route) { return drawRoute(route, now); });
        drawBursts(now);
        context.restore();

        if (elements.sweep) {
            elements.sweep.style.setProperty('--cyber-scan-angle', ((now * 0.018) % 360).toFixed(2) + 'deg');
        }
        updateStats(now);
    }

    function seedScene() {
        var now = performance.now();
        var seedCount = reducedMotion ? 7 : 22;
        for (var index = 0; index < seedCount; index += 1) {
            spawnRoute(now, randomBetween(0.04, 0.78));
        }
        for (var feedIndex = 0; feedIndex < 7; feedIndex += 1) {
            var route = routes[(feedIndex * 2) % routes.length];
            if (route) createEventRow(route);
        }
        nextSpawnAt = now + 180;
    }

    function resetIdleTimer() {
        scene.classList.remove('is-interface-idle');
        window.clearTimeout(idleTimer);
        idleTimer = window.setTimeout(function () {
            if (!scene.matches(':focus-within')) scene.classList.add('is-interface-idle');
        }, 4800);
    }

    function setFocusMode(force) {
        var enabled = typeof force === 'boolean' ? force : !scene.classList.contains('is-focus-mode');
        scene.classList.toggle('is-focus-mode', enabled);
        var button = scene.querySelector('[data-cyber-action="focus"]');
        if (button) button.setAttribute('aria-pressed', String(enabled));
        window.setTimeout(resizeCanvas, 700);
        resetIdleTimer();
    }

    function toggleFullscreen() {
        var operation;
        if (document.fullscreenElement) {
            operation = document.exitFullscreen();
        } else if (scene.requestFullscreen) {
            operation = scene.requestFullscreen({ navigationUI: 'hide' });
        }
        if (operation && typeof operation.catch === 'function') operation.catch(function () {});
        resetIdleTimer();
    }

    function exitScene() {
        var destination = scene.getAttribute('data-exit-url') || './?view=cases#cases';
        window.location.assign(destination);
    }

    scene.addEventListener('click', function (event) {
        var button = event.target.closest('[data-cyber-action]');
        if (!button) return;
        var action = button.getAttribute('data-cyber-action');
        if (action === 'fullscreen') toggleFullscreen();
        if (action === 'focus') setFocusMode();
        if (action === 'exit') exitScene();
    });

    document.addEventListener('keydown', function (event) {
        if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return;
        var key = event.key.toLowerCase();
        if (key === 'f') {
            event.preventDefault();
            toggleFullscreen();
        } else if (key === 'm') {
            event.preventDefault();
            setFocusMode();
        } else if (event.key === 'Escape' && !document.fullscreenElement) {
            if (scene.classList.contains('is-focus-mode')) setFocusMode(false);
            else exitScene();
        }
        resetIdleTimer();
    });

    ['pointermove', 'pointerdown', 'touchstart'].forEach(function (eventName) {
        scene.addEventListener(eventName, resetIdleTimer, { passive: true });
    });

    document.addEventListener('fullscreenchange', function () {
        var enabled = Boolean(document.fullscreenElement);
        scene.classList.toggle('is-fullscreen', enabled);
        var button = scene.querySelector('[data-cyber-action="fullscreen"] span');
        if (button) button.textContent = enabled ? 'Windowed' : 'Fullscreen';
        window.setTimeout(resizeCanvas, 120);
    });

    document.addEventListener('visibilitychange', function () {
        isVisible = !document.hidden;
        if (isVisible) {
            var now = performance.now();
            routes.forEach(function (route) { route.bornAt = now - randomBetween(0.05, 0.65) * route.duration; });
            nextSpawnAt = now + 100;
        }
    });

    function handleMotionPreference(event) {
        reducedMotion = event.matches;
        if (reducedMotion && routes.length > 11) routes = routes.slice(-11);
    }
    if (typeof reducedMotionQuery.addEventListener === 'function') {
        reducedMotionQuery.addEventListener('change', handleMotionPreference);
    } else if (typeof reducedMotionQuery.addListener === 'function') {
        reducedMotionQuery.addListener(handleMotionPreference);
    }

    if (typeof ResizeObserver === 'function') {
        new ResizeObserver(resizeCanvas).observe(canvas);
    } else {
        window.addEventListener('resize', resizeCanvas, { passive: true });
    }

    resizeCanvas();
    seedScene();
    loadMap();
    resetIdleTimer();
    animationFrame = window.requestAnimationFrame(animate);

    window.addEventListener('pagehide', function () {
        window.cancelAnimationFrame(animationFrame);
        window.clearTimeout(idleTimer);
    }, { once: true });
}());
