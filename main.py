from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import List

app = FastAPI()

class MotionEvent(BaseModel):
    timestamp: datetime

motion_events: List[MotionEvent] = []

@app.get("/motion-events", response_model=List[MotionEvent])
def get_motion_events():
    return motion_events

@app.post("/motion-events", response_model=MotionEvent)
def add_motion_event(event: MotionEvent):
    motion_events.append(event)
    return event
