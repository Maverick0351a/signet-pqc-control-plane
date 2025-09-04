"""Control plane augmentation layer providing CBOM baseline, ingestion, drift receipts.

Endpoints are attached to the existing FastAPI `app` exported by `spcp.api.main`.
Run with: uvicorn control_plane.api:app
"""
