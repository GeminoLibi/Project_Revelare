-- Populate game data with basic structure for all three games
UPDATE game_data SET game_config = '{
  "worldMap": {
    "0,0,0": {
      "name": "Your Office",
      "description": "Your dingy office on the third floor of a building that''s seen better days.",
      "exits": {"south": "0,1,0"},
      "items": ["case_file", "whiskey"],
      "features": ["desk", "poster", "crack"],
      "npcs": []
    }
  },
  "npcStats": {
    "bartender": {
      "name": "Bartender",
      "description": "A gruff old-timer who knows everyone''s business.",
      "schedule": "always",
      "dialogue": "What''ll it be, pal?",
      "stats": {"charisma": 2, "intelligence": 1}
    }
  },
  "items": {
    "case_file": {
      "name": "Case File",
      "description": "A manila folder containing the details of your current case.",
      "type": "evidence",
      "value": 0
    },
    "whiskey": {
      "name": "Whiskey",
      "description": "A half-empty bottle of cheap whiskey.",
      "type": "consumable",
      "value": 5
    }
  },
  "features": {
    "desk": {
      "name": "Desk",
      "description": "A battered wooden desk covered in papers and coffee stains.",
      "interactable": true
    },
    "poster": {
      "name": "Poster",
      "description": "A faded poster advertising a boxing match from 1945.",
      "interactable": false
    }
  },
  "npcs": {
    "bartender": {
      "name": "Bartender",
      "description": "A gruff old-timer who knows everyone''s business.",
      "location": "bar",
      "schedule": "always",
      "dialogue": "What''ll it be, pal?",
      "stats": {"charisma": 2, "intelligence": 1}
    }
  }
}' WHERE game_type = 'noir';

UPDATE game_data SET game_config = '{
  "worldMap": {
    "0,0,0": {
      "name": "Neon Alley",
      "description": "A cyberpunk street filled with neon lights and digital graffiti.",
      "exits": {"north": "0,-1,0", "south": "0,1,0"},
      "items": ["neural_interface", "energy_drink"],
      "features": ["hologram_display", "data_terminal"],
      "npcs": []
    }
  },
  "npcStats": {
    "hacker": {
      "name": "Street Hacker",
      "description": "A cyberpunk with glowing implants and a datajack.",
      "schedule": "always",
      "dialogue": "Need some intel, choom?",
      "stats": {"intelligence": 3, "charisma": 1}
    }
  },
  "items": {
    "neural_interface": {
      "name": "Neural Interface",
      "description": "A cybernetic implant for direct neural connection to the net.",
      "type": "cyberware",
      "value": 1000
    },
    "energy_drink": {
      "name": "Energy Drink",
      "description": "A can of synthetic energy drink that tastes like battery acid.",
      "type": "consumable",
      "value": 10
    }
  },
  "features": {
    "hologram_display": {
      "name": "Hologram Display",
      "description": "A floating holographic display showing news and advertisements.",
      "interactable": true
    },
    "data_terminal": {
      "name": "Data Terminal",
      "description": "A public access terminal for browsing the net.",
      "interactable": true
    }
  },
  "npcs": {
    "hacker": {
      "name": "Street Hacker",
      "description": "A cyberpunk with glowing implants and a datajack.",
      "location": "alley",
      "schedule": "always",
      "dialogue": "Need some intel, choom?",
      "stats": {"intelligence": 3, "charisma": 1}
    }
  }
}' WHERE game_type = 'cyberpunk';

UPDATE game_data SET game_config = '{
  "worldMap": {
    "0,0,0": {
      "name": "Mystic Grove",
      "description": "An ancient forest filled with magical energy and mystical creatures.",
      "exits": {"north": "0,-1,0", "south": "0,1,0"},
      "items": ["magic_scroll", "healing_potion"],
      "features": ["ancient_tree", "magic_circle"],
      "npcs": []
    }
  },
  "npcStats": {
    "wizard": {
      "name": "Wise Wizard",
      "description": "An ancient wizard with a long white beard and twinkling eyes.",
      "schedule": "always",
      "dialogue": "Greetings, young adventurer. What brings you to my grove?",
      "stats": {"intelligence": 4, "charisma": 2}
    }
  },
  "items": {
    "magic_scroll": {
      "name": "Magic Scroll",
      "description": "A scroll containing ancient magical knowledge.",
      "type": "magic",
      "value": 50
    },
    "healing_potion": {
      "name": "Healing Potion",
      "description": "A glowing red potion that restores health.",
      "type": "consumable",
      "value": 25
    }
  },
  "features": {
    "ancient_tree": {
      "name": "Ancient Tree",
      "description": "A massive oak tree that seems to pulse with magical energy.",
      "interactable": true
    },
    "magic_circle": {
      "name": "Magic Circle",
      "description": "A circle of glowing runes carved into the ground.",
      "interactable": true
    }
  },
  "npcs": {
    "wizard": {
      "name": "Wise Wizard",
      "description": "An ancient wizard with a long white beard and twinkling eyes.",
      "location": "grove",
      "schedule": "always",
      "dialogue": "Greetings, young adventurer. What brings you to my grove?",
      "stats": {"intelligence": 4, "charisma": 2}
    }
  }
}' WHERE game_type = 'fantasy';
