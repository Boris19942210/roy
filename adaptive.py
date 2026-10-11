"""
ROY Adaptive: Адаптация к ресурсам устройства.
"""

import psutil
import time
from typing import Optional


class AdaptiveNode:
    """Управляет активностью узла в зависимости от ресурсов."""
    
    def __init__(self):
        self.cpu_limit = 0.10
        self.battery_threshold = 0.20
        self.idle_threshold = 0.05
        self.max_cpu = 0.30
        
        self.mode = "normal"
        self.max_connections = 20
        self.chunk_size = 128 * 1024  # 128 KB
        self.enable_upload = True
        self.dht_announce_interval = 60
    
    def check_resources(self) -> str:
        """Проверяет текущее состояние ресурсов."""
        cpu_usage = psutil.cpu_percent(interval=0.1) / 100
        battery = self._get_battery()
        
        if cpu_usage > self.max_cpu:
            return "throttle"
        elif battery is not None and battery < self.battery_threshold:
            return "low_power"
        elif cpu_usage < self.idle_threshold:
            return "full_power"
        else:
            return "normal"
    
    def _get_battery(self) -> Optional[float]:
        """Пытается получить уровень батареи."""
        try:
            battery = psutil.sensors_battery()
            if battery:
                return battery.percent / 100
        except:
            pass
        return None
    
    def adjust(self, mode: str):
        """Применяет настройки в зависимости от режима."""
        self.mode = mode
        
        if mode == "throttle":
            self.max_connections = 5
            self.chunk_size = 64 * 1024
            self.enable_upload = False
            self.dht_announce_interval = 300
        elif mode == "low_power":
            self.max_connections = 2
            self.chunk_size = 32 * 1024
            self.enable_upload = False
            self.dht_announce_interval = 600
        elif mode == "full_power":
            self.max_connections = 50
            self.chunk_size = 512 * 1024
            self.enable_upload = True
            self.dht_announce_interval = 30
        else:  # normal
            self.max_connections = 20
            self.chunk_size = 128 * 1024
            self.enable_upload = True
            self.dht_announce_interval = 60
    
    def get_status(self) -> dict:
        """Возвращает текущий статус."""
        return {
            "mode": self.mode,
            "max_connections": self.max_connections,
            "chunk_size": self.chunk_size,
            "enable_upload": self.enable_upload,
            "dht_announce_interval": self.dht_announce_interval,
        }