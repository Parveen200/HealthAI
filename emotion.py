import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)

import nltk
from nltk.sentiment.vader import SentimentIntensityAnalyzer
from transformers import BertTokenizer, TFBertForSequenceClassification
import tensorflow as tf

nltk.download('vader_lexicon')
nltk.download('punkt')

# Load the VADER SentimentIntensityAnalyzer
sia = SentimentIntensityAnalyzer()

# Load the BERT tokenizer and model
model_name = "nlptown/bert-base-multilingual-uncased-sentiment"
tokenizer = BertTokenizer.from_pretrained(model_name)
model = TFBertForSequenceClassification.from_pretrained(model_name)

# Define coping mechanisms with detailed information and video links
coping_mechanisms = {
    'positive': {
        'recommendations': [
            "Keep a gratitude journal: Write down things you are grateful for each day.",
            "Engage in physical exercise: Exercise helps in boosting your mood and improving your overall well-being."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=9WgP4u5mY7s"  # Example video link
        ]
    },
    'negative': {
        'recommendations': [
            "Practice deep breathing: Helps in calming your mind and reducing stress.",
            "Talk to a friend or therapist: Sharing your feelings can be therapeutic."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=2Z45P1bu5xk"  # Example video link
        ]
    },
    'neutral': {
        'recommendations': [
            "Try to relax and take things one step at a time: Helps in reducing anxiety and improving focus."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=5NYYVZj55sE"  # Example video link
        ]
    },
    'happy': {
        'recommendations': [
            "Engage in a hobby: Doing something you love can enhance your happiness.",
            "Spend time with loved ones: Social connections boost your mood."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=1vUq5JS7FzI"  # Example video link
        ]
    },
    'sad': {
        'recommendations': [
            "Listen to uplifting music: Music can lift your spirits and improve your mood.",
            "Practice mindfulness: Helps in being present and easing negative thoughts."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=-f0cqE66cTo"  # Example video link
        ]
    },
    'angry': {
        'recommendations': [
            "Go for a walk: Physical activity can help in managing anger.",
            "Try relaxation exercises: Techniques like deep breathing can reduce anger."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=7z2wE1ufgks"  # Example video link
        ]
    },
    'fearful': {
        'recommendations': [
            "Talk to someone you trust: Sharing your fears can help in alleviating them.",
            "Practice deep breathing: Helps in calming your nerves and reducing anxiety."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=8kMzw8hXGpE"  # Example video link
        ]
    },
    'surprised': {
        'recommendations': [
            "Reflect on the positive aspects: Focus on the good things in your life.",
            "Share your thoughts with someone: Talking about your surprise can help process it."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=0DURrdFJufY"  # Example video link
        ]
    },
    'disgusted': {
        'recommendations': [
            "Take a break: Stepping away from the source of disgust can help.",
            "Engage in a different activity: Distracting yourself can improve your mood."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=9Vkp1h31i28"  # Example video link
        ]
    },
    'bored': {
        'recommendations': [
            "Try a new hobby: Engaging in a new activity can alleviate boredom.",
            "Learn something new: Acquiring new skills can be stimulating."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ"  # Example video link
        ]
    },
    'anxious': {
        'recommendations': [
            "Practice relaxation techniques: Methods like meditation can help in reducing anxiety.",
            "Speak with a mental health professional: Professional guidance can be beneficial."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=VZqaybwbHeQ"  # Example video link
        ]
    },
    'confident': {
        'recommendations': [
            "Continue setting and achieving goals: Maintain your momentum by setting new goals.",
            "Share your success: Celebrating your achievements can boost your confidence further."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=Vx8PpupW3gQ"  # Example video link
        ]
    },
    'overwhelmed': {
        'recommendations': [
            "Break tasks into smaller steps: Tackling smaller tasks can make things feel more manageable.",
            "Practice mindfulness: Being present can help reduce feelings of being overwhelmed."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=6dP7tsLczhQ"  # Example video link
        ]
    },
    'tired': {
        'recommendations': [
            "Get adequate rest: Ensure you have a proper sleep schedule to recover energy.",
            "Take short breaks: Short breaks during tasks can help reduce fatigue."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=zz2P7aDRZcI"  # Example video link
        ]
    },
    'excited': {
        'recommendations': [
            "Channel your excitement into productive activities: Use your enthusiasm to start new projects.",
            "Share your excitement with others: Talking about your excitement can enhance your experience."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=Idt4DD3sN0A"  # Example video link
        ]
    },
    'grateful': {
        'recommendations': [
            "Express gratitude to others: Share your appreciation with people around you.",
            "Keep a gratitude journal: Regularly note down things you're thankful for."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=Grg5vL2ViG4"  # Example video link
        ]
    },
    'guilty': {
        'recommendations': [
            "Acknowledge your feelings: Understanding why you feel guilty can help in processing the emotion.",
            "Take responsibility and make amends: If possible, address the cause of your guilt."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=9R9m0zFAF4Q"  # Example video link
        ]
    },
    'hopeful': {
        'recommendations': [
            "Set positive goals: Focus on optimistic future plans.",
            "Visualize success: Imagining successful outcomes can enhance motivation."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=YkN6XjG9P7Q"  # Example video link
        ]
    },
    'regretful': {
        'recommendations': [
            "Reflect and learn: Analyze what led to regret and use it as a learning opportunity.",
            "Forgive yourself: Understand that everyone makes mistakes and move forward."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=TkJLoBXY_E4"  # Example video link
        ]
    },
    'embarrassed': {
        'recommendations': [
            "Practice self-compassion: Be kind to yourself and understand that everyone has awkward moments.",
            "Talk it out: Sometimes sharing your embarrassment can reduce its intensity."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=thclZ81ldEA"  # Example video link
        ]
    },
    'lonely': {
        'recommendations': [
            "Reach out to friends or family: Connecting with others can alleviate feelings of loneliness.",
            "Engage in social activities: Participating in group activities can help reduce isolation."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=7dV5biH6rDk"  # Example video link
        ]
    },
    'frustrated': {
        'recommendations': [
            "Identify the source of frustration: Understanding the cause can help in managing it.",
            "Take a break and return later: Sometimes stepping away can provide a new perspective."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=q9LltDL9Z2U"  # Example video link
        ]
    },
    'disappointed': {
        'recommendations': [
            "Accept your feelings: Recognize and process your disappointment.",
            "Focus on what you can control: Redirect your energy towards achievable goals."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=E6WXsy-ZLQQ"  # Example video link
        ]
    },
    'content': {
        'recommendations': [
            "Maintain your current practices: Continue doing what’s working well.",
            "Share your contentment: Expressing your satisfaction can enhance your feelings."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=8F3Q1EJh2uE"  # Example video link
        ]
    },
    'motivated': {
        'recommendations': [
            "Set new goals: Use your motivation to set and achieve new objectives.",
            "Stay organized: Keeping track of your progress can help maintain your motivation."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=UuRbPPf_5VE"  # Example video link
        ]
    },
    'shocked': {
        'recommendations': [
            "Take time to process: Allow yourself time to absorb and understand the shock.",
            "Seek support: Talking with someone can help in processing shocking news."
        ],
        'videos': [
            "https://www.youtube.com/watch?v=Yz1_D4A8HgQ"  # Example video link
        ]
    }
}
def analyze_sentiment_vader(text):
    return sia.polarity_scores(text)

def analyze_sentiment_bert(text):
    inputs = tokenizer(text, return_tensors="tf")
    outputs = model(inputs)
    probs = tf.nn.softmax(outputs.logits, axis=-1)
    return probs

def recommend_coping_mechanisms(sentiment_score):
    compound_score = sentiment_score['compound']
    if compound_score >= 0.05:
        return coping_mechanisms['positive']
    elif compound_score <= -0.05:
        return coping_mechanisms['negative']
    else:
        return coping_mechanisms['neutral']
