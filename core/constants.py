"""Shared constants and tunables."""

CORE_REVISION = "4A-r01-modular"

NO_DATA = "No Data"

# Centroid weighting
RSSI_REF = -90.0
RSSI_SCALE = 8.0
ACC_FLOOR_M = 5.0
ACC_DEFAULT_M = 25.0
DROP_WEAKEST_FRAC = 0.10

# KML
KML_CIRCLE_POINTS = 36

# Leaflet assets (bundled locally; fallback CDN only if local missing)
LEAFLET_CSS_LOCAL = "leaflet/leaflet.css"
LEAFLET_JS_LOCAL = "leaflet/leaflet.js"
LEAFLET_CSS_CDN = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
LEAFLET_JS_CDN = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
