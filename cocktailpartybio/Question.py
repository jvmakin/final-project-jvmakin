__author__ = 'Jani'
import itertools
import csv
import random

# This class creates a question with question text and four answers with a number (the last value) to indicate the correct answer
class Question:
    newid = itertools.count().next #I'm not actually using this function, but if necessary this creates an id for a given question
    def __init__(self, q_text, a_1, a_2, a_3, a_4, c_a):

        self.id = Question.newid()
        self.q_text = q_text    #question text
        self.a_1 = a_1          #answer 1
        self.a_2 = a_2          #answer 2
        self.a_3 = a_3          #answer 3
        self.a_4 = a_4          #answer 4
        if (c_a == 1):          #sets the correct answer to one of the answers based on the number
            self.correct = a_1
        elif (c_a == 2):
            self.correct = a_2
        elif (c_a == 3):
            self.correct = a_3
        else:
            self.correct = a_4

    def correct_answer(self, answer):   #returns true if the answer is correct, false o/w
        if (answer == self.correct):
            return True
        return False

    def get_questiontext(self):         #returns question text
        return self.q_text

    def get_answerstext(self, i):       #returns answer text for a specific index (1, 2, 3, or 4)
        if i == 1:
            return self.a_1
        elif i == 2:
            return self.a_2
        elif i == 3:
            return self.a_3
        elif i == 4:
            return self.a_4
        else:
            return 'no such answer'

# This class creates an array of Question objects and correct answers out of a csv file based on the level entered
class Test:

    def __init__(self, type):   

        self.type = type    #the type is the level
        infile = 'Questions/Questions' + str(type) + ".csv"
        count = 0
        with open(infile,"rb") as source:
            rdr = csv.reader( source )
            for j,r in enumerate(rdr):
                if j > 0:
                    count += 1
        questions = random.sample(range(1, count+1), 5)     #generates five random question numbers to add
        Questions = []
        Answers = []
        with open(infile,"rb") as source:
            rdr = csv.reader( source )
            for j,r in enumerate(rdr):
                if j == 0:
                    firstline = r
                if j > 0 and j in questions:

                    Questions.append(Question(r[0], r[1], r[2], r[3], r[4], r[5]))
                    Answers.append(r[5])
        self.questions = Questions
        self.answers = Answers

    def get_questions(self):        #returns the question array

        return self.questions

    def get_answers(self):          #returns the answer array

        return self.answers

    def answer_string(self):        #returns the correct answers (in number form) as a string

        a_string = ''
        for A in self.answers:
            a_string += A
        return a_string


