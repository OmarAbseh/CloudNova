import json
import os

knowledge_base = []


with open("ai/assistant_knowledge.json", "r", encoding="utf-8") as f:
    knowledge_base = json.load(f)

def find_best_answer(user_input):
    user_input = user_input.lower()
    best_match = None
    highest_score = 0

    for item in knowledge_base:
        for keyword in item.get("keywords", []):
            keyword = keyword.lower()
            if keyword in user_input:
                score = len(keyword)
                if score > highest_score:
                    highest_score = score
                    best_match = item["answer"]

    if best_match:
        return best_match
    else:
        return "I'm not sure yet, but I'm still learning! Try asking about threats, fixes, AI score, or CloudMind."
